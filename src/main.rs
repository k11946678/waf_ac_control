//! ac-control — manage per-domain access profiles for nginx from your phone.
//!
//! Profiles per domain:
//!   allow-all       no restriction
//!   countries       only listed ISO country codes + whitelisted IPs may pass
//!   whitelist-only  only whitelisted IPs (global + per-domain) may pass
//!   block-all       everyone gets 503 (maintenance) — even whitelisted IPs
//!
//! Blocked requests get a `503` maintenance response, not a connection error.
//!
//! Scanner protection: configurable hot paths (phpmyadmin, .env, .git/, …) are
//! matched case-insensitively against the request URI. Hits are always logged
//! to a dedicated probe log (browsable in the UI under "Probes"), and when the
//! feature is enabled they are also blocked instantly with 444 (connection
//! drop) or 404 (not found).
//!
//! Files owned by this tool (keep them out of ansible's template loops):
//!   /etc/nginx/access-control/state.json   — persisted state (source of truth)
//!   /etc/nginx/access-control/http.conf     — generated maps (http context)
//!   /etc/nginx/access-control/server.conf  — snippet included in every server {}
//!
//! Wiring (add once to your ansible templates):
//!   1. http context:     include /etc/nginx/access-control/http.conf;
//!   2. every server {}:  include /etc/nginx/access-control/server.conf;
//!
//! Build:  cargo build --release
//!
//! Env (all optional):
//!   AC_LISTEN     default 127.0.0.1:8080
//!   AC_PREFIX     default /proxy/     (public URL path the UI is served under)
//!   AC_DIR        default /etc/nginx/access-control
//!   AC_SITE_DIRS  default /etc/nginx/sites-enabled,/etc/nginx/conf.d
//!   AC_GEOIP_DB   default /usr/share/GeoIP/GeoLite2-Country.mmdb
//!   AC_NGINX_BIN  default nginx
//!   AC_RELOAD_CMD default "systemctl reload nginx"
//!   AC_PROBE_LOG  default /var/log/nginx/ac-probes.log
//!
//! The tool has no auth of its own: bind it to localhost and expose it through
//! an nginx `location /proxy/ { proxy_pass http://127.0.0.1:8080; }` block
//! with HTTPS + auth_basic scoped to that location (see chat notes).

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::OnceLock,
};

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Ctx {
    dir: PathBuf,
    site_dirs: Vec<PathBuf>,
    geoip_db: PathBuf,
    nginx_bin: String,
    reload_cmd: Vec<String>,
    listen: String,
    probe_log: PathBuf,
    prefix: String,
}

/// Normalize a URL path prefix: always a leading and trailing slash.
/// Empty input becomes "/" (UI served at the vhost root).
fn normalize_prefix(p: &str) -> String {
    let p = p.trim();
    let mut out = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    };
    if !out.ends_with('/') {
        out.push('/');
    }
    out
}

impl Ctx {
    fn from_env() -> Self {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Ctx {
            dir: PathBuf::from(env("AC_DIR", "/etc/nginx/access-control")),
            site_dirs: env("AC_SITE_DIRS", "/etc/nginx/sites-enabled,/etc/nginx/conf.d")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect(),
            geoip_db: PathBuf::from(env("AC_GEOIP_DB", "/usr/share/GeoIP/GeoLite2-Country.mmdb")),
            nginx_bin: env("AC_NGINX_BIN", "nginx"),
            reload_cmd: env("AC_RELOAD_CMD", "systemctl reload nginx")
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            listen: env("AC_LISTEN", "127.0.0.1:8080"),
            probe_log: PathBuf::from(env("AC_PROBE_LOG", "/var/log/nginx/ac-probes.log")),
            prefix: normalize_prefix(&env("AC_PREFIX", "/proxy/")),
        }
    }
}

// ---------------------------------------------------------------------------
// state model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Profile {
    AllowAll,
    Countries,
    WhitelistOnly,
    BlockAll,
}

impl Default for Profile {
    fn default() -> Self {
        Profile::AllowAll
    }
}

impl Profile {
    fn as_str(self) -> &'static str {
        match self {
            Profile::AllowAll => "allow-all",
            Profile::Countries => "countries",
            Profile::WhitelistOnly => "whitelist-only",
            Profile::BlockAll => "block-all",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainState {
    #[serde(default)]
    profile: Profile,
    /// ISO 3166-1 alpha-2, stored uppercase. Only used by `countries`.
    #[serde(default)]
    countries: Vec<String>,
    /// Exact IPs. Only used by `countries` and `whitelist-only`.
    #[serde(default)]
    whitelist: Vec<String>,
}

impl Default for DomainState {
    fn default() -> Self {
        DomainState {
            profile: Profile::AllowAll,
            countries: Vec::new(),
            whitelist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum HotAction {
    Drop,
    NotFound,
}

impl Default for HotAction {
    fn default() -> Self {
        HotAction::Drop
    }
}

impl HotAction {
    fn as_str(self) -> &'static str {
        match self {
            HotAction::Drop => "drop",
            HotAction::NotFound => "not-found",
        }
    }
}

/// Default scanner hot paths: regex fragments matched against `$uri`.
const DEFAULT_SCANNER_PATTERNS: &[&str] = &[
    r#"^/phpmyadmin"#,
    r#"^/\.env"#,
    r#"^/\.aws/"#,
    r#"^/\.git/"#,
    r#"^/wp-admin(/|$)"#,
    r#"config\.php$"#,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HotPath {
    enabled: bool,
    action: HotAction,
    patterns: Vec<String>,
}

impl Default for HotPath {
    fn default() -> Self {
        HotPath {
            enabled: true,
            action: HotAction::Drop,
            patterns: DEFAULT_SCANNER_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct AppState {
    /// Global IPs/CIDRs that bypass `countries` and `whitelist-only`.
    #[serde(default)]
    global_whitelist: Vec<String>,
    /// Scanner hot-path protection (probe detection + optional blocking).
    #[serde(default)]
    hotpath: HotPath,
    #[serde(default)]
    domains: BTreeMap<String, DomainState>,
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn state_path(ctx: &Ctx) -> PathBuf {
    ctx.dir.join("state.json")
}

fn load_state(ctx: &Ctx) -> Result<AppState, String> {
    let p = state_path(ctx);
    if !p.exists() {
        return Ok(AppState::default());
    }
    let raw = fs::read_to_string(&p).map_err(|e| format!("reading {}: {e}", p.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parsing {}: {e}", p.display()))
}

fn atomic_write(path: &PathBuf, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("renaming {}: {e}", tmp.display()))
}

fn run(cmd: &[String]) -> Result<String, String> {
    let (prog, args) = cmd.split_first().ok_or("empty command")?;
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("running {prog}: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(text.trim().to_string())
    }
}

/// True if nginx was built with the geoip2 module (`nginx -V` configure args).
fn geoip_available(ctx: &Ctx) -> bool {
    static G: OnceLock<bool> = OnceLock::new();
    *G.get_or_init(|| {
        let s = run(&[ctx.nginx_bin.clone(), "-V".to_string()]).unwrap_or_default();
        s.contains("geoip2")
    })
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && !d.starts_with('~')
        && !d.starts_with('$')
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '_'))
}

fn valid_ip_or_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, len)) => {
            let Ok(v) = ip.parse::<IpAddr>() else {
                return false;
            };
            let Ok(n) = len.parse::<u8>() else {
                return false;
            };
            n <= if v.is_ipv4() { 32 } else { 128 }
        }
        None => s.parse::<IpAddr>().is_ok(),
    }
}

// ---------------------------------------------------------------------------
// nginx config generation
// ---------------------------------------------------------------------------

/// Content of `server.conf`, included once inside every server { } block.
/// Scanner probes are blocked first (444/404), then the profile decision (503).
/// Matching probes are always logged, even when blocking is disabled.
fn render_server(ctx: &Ctx) -> String {
    format!(
        concat!(
            "# Generated by ac-control — include this once inside every server {{ }} block.\n",
            "# Scanner probes first (444 drop / 404 not-found), then the profile block (503).\n",
            "if ($ac_hot_drop) {{ return 444; }}\n",
            "if ($ac_hot_404) {{ return 404; }}\n",
            "if ($ac_block) {{ return 503; }}\n",
            "access_log {} ac_probe if=$ac_hot_hit;\n",
        ),
        ctx.probe_log.display()
    )
}

/// Render `http.conf`: http-context maps and geo blocks implementing the state.
fn render_http(state: &AppState, ctx: &Ctx) -> Result<String, String> {
    let use_cc = state
        .domains
        .values()
        .any(|d| d.profile == Profile::Countries);

    if use_cc {
        if !geoip_available(ctx) {
            return Err("the nginx geoip2 module is not available — install it \
                 (e.g. apt install libnginx-mod-http-geoip2) to use country profiles"
                .into());
        }
        if !ctx.geoip_db.exists() {
            return Err(format!(
                "GeoIP database not found at {} — install GeoLite2-Country.mmdb \
                 (e.g. via geoipupdate) or point AC_GEOIP_DB at it",
                ctx.geoip_db.display()
            ));
        }
    }

    let mut out = String::new();
    out.push_str("# Generated by ac-control — DO NOT EDIT.\n");
    out.push_str("# Source of truth: state.json next to this file.\n\n");

    // 1. country variable: real geoip2 lookup, or a stub so references stay valid
    if use_cc {
        out.push_str("# Country lookup (MaxMind GeoLite2).\n");
        out.push_str(&format!("geoip2 {} {{\n", ctx.geoip_db.display()));
        out.push_str("    auto_reload 5m;\n");
        out.push_str("    $ac_country country iso_code;\n");
        out.push_str("}\n\n");
    } else {
        out.push_str("# No country profile active — country check stubbed to 0.\n");
        out.push_str("geo $ac_country { default 0; }\n\n");
    }

    // 2. per-domain allowed countries
    out.push_str("# Per-domain allowed countries (whitelisted IPs bypass this).\n");
    out.push_str("map \"$host|$ac_country\" $ac_cc {\n    default 0;\n");
    for (name, d) in &state.domains {
        if d.profile != Profile::Countries {
            continue;
        }
        for cc in &d.countries {
            out.push_str(&format!("    \"{name}|{cc}\" 1;\n"));
        }
    }
    out.push_str("}\n\n");

    // 3. global whitelist (geo supports CIDR)
    out.push_str("# Global whitelist — exact IPs or CIDR ranges.\n");
    out.push_str("geo $ac_gw {\n    default 0;\n");
    for ip in &state.global_whitelist {
        out.push_str(&format!("    {ip} 1;\n"));
    }
    out.push_str("}\n\n");

    // 4. per-domain whitelist (exact IPs, host-pinned)
    out.push_str("# Per-domain IP whitelist (exact IPs only).\n");
    out.push_str("map \"$host|$remote_addr\" $ac_wl {\n    default 0;\n");
    for (name, d) in &state.domains {
        for ip in &d.whitelist {
            out.push_str(&format!("    \"{name}|{ip}\" 1;\n"));
        }
    }
    out.push_str("}\n\n");

    // 5. profile per host; unlisted hosts stay on allow-all
    out.push_str("# Active profile per host.\n");
    out.push_str("map $host $ac_profile {\n    default \"allow-all\";\n");
    for (name, d) in &state.domains {
        if d.profile != Profile::AllowAll {
            out.push_str(&format!("    \"{name}\" \"{}\";\n", d.profile.as_str()));
        }
    }
    out.push_str("}\n\n");

    // 6. final decision (exact enumeration — no regex subtleties)
    out.push_str(concat!(
        "# Final decision: 1 = block with 503.\n",
        "# fields: profile | global-whitelist | per-domain-whitelist | country-ok\n",
        "map \"$ac_profile|$ac_gw|$ac_wl|$ac_cc\" $ac_block {\n",
        "    default 0;\n",
        "    \"countries|0|0|0\" 1;\n",
        "    \"whitelist-only|0|0|0\" 1;\n",
        "    \"whitelist-only|0|0|1\" 1;\n",
        "    \"block-all|0|0|0\" 1;\n",
        "    \"block-all|0|0|1\" 1;\n",
        "    \"block-all|0|1|0\" 1;\n",
        "    \"block-all|0|1|1\" 1;\n",
        "    \"block-all|1|0|0\" 1;\n",
        "    \"block-all|1|0|1\" 1;\n",
        "    \"block-all|1|1|0\" 1;\n",
        "    \"block-all|1|1|1\" 1;\n",
        "}\n",
    ));

    // 7. scanner hot-path detection and blocking
    out.push_str(concat!(
        "# Scanner probe log: one line per matching request, independent of blocking.\n",
        "log_format ac_probe '$time_iso8601|$remote_addr|$status|$host|$request';\n",
        "map $uri $ac_hot_hit {\n    default 0;\n",
    ));
    if !state.hotpath.patterns.is_empty() {
        out.push_str(&format!(
            "    \"~*(?:{})\" 1;\n",
            state.hotpath.patterns.join("|")
        ));
    }
    out.push_str("}\n\n");

    // blocking decision: only one of drop/404 is active at a time
    out.push_str(&format!(
        "# Scanner blocking — action: {}{}\n",
        state.hotpath.action.as_str(),
        if state.hotpath.enabled {
            ""
        } else {
            " (disabled)"
        }
    ));
    let (drop_active, notfound_active) = match (state.hotpath.enabled, state.hotpath.action) {
        (true, HotAction::Drop) => (true, false),
        (true, HotAction::NotFound) => (false, true),
        (false, _) => (false, false),
    };
    if drop_active {
        out.push_str("map $ac_hot_hit $ac_hot_drop {\n    default 0;\n    1 1;\n}\n\n");
    } else {
        out.push_str("map $ac_hot_hit $ac_hot_drop {\n    default 0;\n}\n\n");
    }
    if notfound_active {
        out.push_str("map $ac_hot_hit $ac_hot_404 {\n    default 0;\n    1 1;\n}\n");
    } else {
        out.push_str("map $ac_hot_hit $ac_hot_404 {\n    default 0;\n}\n");
    }

    Ok(out)
}

/// Persist state, regenerate configs, validate with `nginx -t`, reload nginx.
/// On a failed test both files are rolled back so nginx keeps its valid config.
fn apply(ctx: &Ctx, new_state: &AppState) -> Result<(), String> {
    let http = render_http(new_state, ctx)?;
    let http_path = ctx.dir.join("http.conf");
    let old_http = fs::read_to_string(&http_path).ok();
    let old_state = fs::read_to_string(state_path(ctx)).ok();

    atomic_write(
        &state_path(ctx),
        &serde_json::to_string_pretty(&new_state).map_err(|e| e.to_string())?,
    )?;
    atomic_write(&http_path, &http)?;

    if let Err(e) = run(&[ctx.nginx_bin.clone(), "-t".to_string()]) {
        if let Some(old) = old_http {
            let _ = atomic_write(&http_path, &old);
        }
        if let Some(old) = old_state {
            let _ = atomic_write(&state_path(ctx), &old);
        }
        return Err(format!("nginx -t rejected the config: {e}"));
    }

    if let Err(e) = run(&ctx.reload_cmd) {
        return Err(format!("config is valid, but the reload failed: {e}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vhost scanning (find server_name entries + wiring status)
// ---------------------------------------------------------------------------

fn strip_comments(s: &str) -> String {
    s.lines()
        .map(|l| match l.find('#') {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_server_names(clean: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = clean.as_bytes();
    let mut from = 0;
    while let Some(rel) = clean[from..].find("server_name") {
        let at = from + rel;
        from = at + "server_name".len();
        let boundary_before =
            at == 0 || matches!(bytes[at - 1], b' ' | b'\t' | b'\n' | b'\r' | b'{' | b';');
        let after = &clean[from..];
        let boundary_after = after.starts_with(|c: char| c.is_whitespace());
        if !(boundary_before && boundary_after) {
            continue;
        }
        let end = after.find(';').unwrap_or(after.len());
        for token in after[..end].split_whitespace() {
            if valid_domain(token) {
                out.push(token.to_ascii_lowercase());
            }
        }
    }
    out
}

/// Returns (domain -> wired?, http-bridge-included?).
/// wired = at least one scanned file with that server_name also includes
/// `access-control/server.conf`.
fn scan_vhosts(ctx: &Ctx) -> (BTreeMap<String, bool>, bool) {
    let mut domains: BTreeMap<String, bool> = BTreeMap::new();
    let mut http_bridge = false;

    let mut process = |content: &str| {
        let clean = strip_comments(content);
        if clean.contains("access-control/http.conf") {
            http_bridge = true;
        }
        let wired = clean.contains("access-control/server.conf");
        for name in extract_server_names(&clean) {
            let e = domains.entry(name).or_insert(false);
            *e = *e || wired;
        }
    };

    if let Ok(c) = fs::read_to_string("/etc/nginx/nginx.conf") {
        process(&c);
    }
    for dir in &ctx.site_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                continue;
            }
            if let Ok(c) = fs::read_to_string(&p) {
                process(&c);
            }
        }
    }
    (domains, http_bridge)
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ApiDomain {
    name: String,
    wired: bool,
    profile: Profile,
    countries: Vec<String>,
    whitelist: Vec<String>,
}

#[derive(Serialize)]
struct ApiState {
    domains: Vec<ApiDomain>,
    global_whitelist: Vec<String>,
    hotpath: HotPath,
    geoip_available: bool,
    geoip_db: String,
    http_bridge: bool,
}

#[derive(Deserialize)]
struct DomainBody {
    profile: Profile,
    #[serde(default)]
    countries: Vec<String>,
    #[serde(default)]
    whitelist: Vec<String>,
}

#[derive(Deserialize)]
struct GlobalBody {
    whitelist: Vec<String>,
}

type ApiError = (StatusCode, String);

async fn api_state(State(ctx): State<Ctx>) -> Json<ApiState> {
    let state = load_state(&ctx).unwrap_or_default();
    let (mut scan, http_bridge) = scan_vhosts(&ctx);
    // include managed domains that no longer appear in any server block
    for name in state.domains.keys() {
        scan.entry(name.clone()).or_insert(false);
    }
    let domains = scan
        .into_iter()
        .map(|(name, wired)| {
            let ds = state.domains.get(&name).cloned().unwrap_or_default();
            ApiDomain {
                name,
                wired,
                profile: ds.profile,
                countries: ds.countries,
                whitelist: ds.whitelist,
            }
        })
        .collect();
    Json(ApiState {
        domains,
        global_whitelist: state.global_whitelist,
        hotpath: state.hotpath,
        geoip_available: geoip_available(&ctx),
        geoip_db: ctx.geoip_db.display().to_string(),
        http_bridge,
    })
}

async fn api_set_domain(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Json(body): Json<DomainBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !valid_domain(&domain) {
        return Err((StatusCode::BAD_REQUEST, "invalid domain name".into()));
    }
    let domain = domain.to_ascii_lowercase();

    let mut countries = Vec::new();
    for c in &body.countries {
        let c = c.trim().to_ascii_uppercase();
        if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid country code {c:?} — use ISO 3166-1 alpha-2 like CH, DE"),
            ));
        }
        if !countries.contains(&c) {
            countries.push(c);
        }
    }
    let mut whitelist = Vec::new();
    for ip in &body.whitelist {
        let ip = ip.trim();
        if ip.parse::<IpAddr>().is_err() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "invalid IP {ip:?} — the per-domain whitelist needs exact IPs; \
                     CIDR ranges only work on the global whitelist"
                ),
            ));
        }
        if !whitelist.iter().any(|x| x == ip) {
            whitelist.push(ip.to_string());
        }
    }
    if body.profile == Profile::Countries && countries.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "the countries profile needs at least one country code".into(),
        ));
    }

    let mut state = load_state(&ctx).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.domains.insert(
        domain.clone(),
        DomainState {
            profile: body.profile,
            countries,
            whitelist,
        },
    );
    apply(&ctx, &state).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;

    let mut warning = None;
    if let Some(host) = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.rsplit_once(':').map(|(h, _)| h).unwrap_or(h))
    {
        if host == domain {
            warning = Some(
                "this is the domain the admin page is served from — \
                 don't lock yourself out"
                    .to_string(),
            );
        }
    }
    Ok(Json(serde_json::json!({ "ok": true, "warning": warning })))
}

async fn api_delete_domain(
    State(ctx): State<Ctx>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let domain = domain.to_ascii_lowercase();
    let mut state = load_state(&ctx).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if state.domains.remove(&domain).is_none() {
        return Err((StatusCode::NOT_FOUND, "domain is not managed".into()));
    }
    apply(&ctx, &state).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn api_set_global(
    State(ctx): State<Ctx>,
    Json(body): Json<GlobalBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut list = Vec::new();
    for entry in &body.whitelist {
        let entry = entry.trim();
        if !valid_ip_or_cidr(entry) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid IP or CIDR {entry:?}"),
            ));
        }
        if !list.iter().any(|x| x == entry) {
            list.push(entry.to_string());
        }
    }
    let mut state = load_state(&ctx).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.global_whitelist = list;
    apply(&ctx, &state).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn api_test(State(ctx): State<Ctx>) -> (StatusCode, String) {
    match run(&[ctx.nginx_bin.clone(), "-t".to_string()]) {
        Ok(o) => (StatusCode::OK, o.trim().to_string()),
        Err(e) => (StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
struct HotPathBody {
    enabled: bool,
    action: HotAction,
    #[serde(default)]
    patterns: Vec<String>,
}

async fn api_set_hotpath(
    State(ctx): State<Ctx>,
    Json(body): Json<HotPathBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut patterns = Vec::new();
    for p in &body.patterns {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if p.contains('"') || p.len() > 200 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid pattern {p:?} — no double quotes, max 200 chars"),
            ));
        }
        if !patterns.iter().any(|x: &String| x == p) {
            patterns.push(p.to_string());
        }
    }
    if patterns.len() > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            "too many patterns (max 100)".into(),
        ));
    }

    let mut state = load_state(&ctx).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.hotpath = HotPath {
        enabled: body.enabled,
        action: body.action,
        patterns,
    };
    apply(&ctx, &state).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Serialize)]
struct Probe {
    time: String,
    ip: String,
    status: String,
    host: String,
    request: String,
}

async fn api_probes(State(ctx): State<Ctx>) -> Json<serde_json::Value> {
    let entries = read_probes(&ctx.probe_log, 150);
    Json(serde_json::json!({ "entries": entries }))
}

/// Tail the probe log and parse the most recent entries, newest first.
fn read_probes(path: &FsPath, limit: usize) -> Vec<Probe> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return Vec::new();
    };
    let tail: u64 = 128 * 1024;
    let start = len.saturating_sub(tail);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = String::new();
    if f.take(tail).read_to_string(&mut buf).is_err() {
        return Vec::new();
    }
    let lines: Vec<&str> = buf.lines().collect();
    let skip = usize::from(start > 0); // first line may be a partial tail cut
    let mut out = Vec::new();
    for line in lines.iter().skip(skip) {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() == 5 {
            out.push(Probe {
                time: parts[0].to_string(),
                ip: parts[1].to_string(),
                status: parts[2].to_string(),
                host: parts[3].to_string(),
                request: parts[4].to_string(),
            });
        }
    }
    out.reverse();
    out.truncate(limit);
    out
}

// ---------------------------------------------------------------------------
// embedded mobile UI
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<base href="__AC_PREFIX__">
<title>nginx access</title>
<style>
* { box-sizing: border-box; margin: 0; }
body { font: 16px/1.4 system-ui, sans-serif; background: #0e1116; color: #e6e9ef; padding-bottom: 60px; }
header { position: sticky; top: 0; z-index: 5; display: flex; align-items: center; gap: 10px;
  padding: 14px 16px; background: rgba(14,17,22,.85); backdrop-filter: blur(8px); border-bottom: 1px solid #232a35; }
header h1 { font-size: 17px; font-weight: 600; flex: 1; }
button { font: inherit; }
.gear { background: none; border: 1px solid #2c3542; color: #e6e9ef; border-radius: 10px; padding: 6px 10px; cursor: pointer; }
.banner { margin: 12px 16px 0; padding: 10px 12px; border-radius: 12px; font-size: 13px; }
.warn { background: #3b2f14; color: #ffd479; border: 1px solid #6b561f; }
.info { background: #14273b; color: #7cc0ff; border: 1px solid #1f4d6e; }
code { font-family: ui-monospace, monospace; font-size: 12px; background: #232a35; padding: 1px 5px; border-radius: 6px; }
.domain { display: flex; align-items: center; gap: 10px; margin: 10px 16px; padding: 14px;
  background: #171c24; border: 1px solid #232a35; border-radius: 14px; cursor: pointer; }
.domain:active { background: #1d2330; }
.domain .name { flex: 1; font-weight: 600; font-size: 15px; word-break: break-all; }
.domain .name small { display: block; color: #ffd479; font-weight: 400; font-size: 11px; margin-top: 3px; }
.chip { font-size: 11px; font-weight: 700; padding: 5px 9px; border-radius: 999px; white-space: nowrap; }
.c-ok { background: #10331c; color: #55d678; }
.c-mid { background: #12333b; color: #55c8d6; }
.c-warn { background: #3b2f14; color: #ffd479; }
.c-bad { background: #3b1418; color: #ff7b84; }
#sheet-back { position: fixed; inset: 0; background: rgba(0,0,0,.6); z-index: 9; display: none; }
#sheet-back.open { display: block; }
#sheet { position: fixed; left: 0; right: 0; bottom: 0; z-index: 10; background: #171c24;
  border-radius: 20px 20px 0 0; border-top: 1px solid #2c3542; padding: 20px 16px 30px;
  max-height: 88vh; overflow-y: auto; display: none; }
#sheet.open { display: block; }
#sheet h2 { font-size: 16px; margin-bottom: 4px; word-break: break-all; }
#sheet .sub { color: #778394; font-size: 12px; margin-bottom: 14px; }
.opt { display: flex; align-items: center; gap: 12px; width: 100%; text-align: left; margin: 8px 0;
  background: #1d2330; border: 2px solid #2c3542; border-radius: 14px; padding: 12px 14px; cursor: pointer; }
.opt.sel { border-color: #4f8cff; background: #1a2740; }
.opt .dot { width: 18px; height: 18px; border-radius: 50%; border: 2px solid #4c5766; flex: none; }
.opt.sel .dot { border-color: #4f8cff; background: #4f8cff; }
.opt b { display: block; font-size: 15px; }
.opt span.d { color: #8a95a5; font-size: 12px; }
label { display: block; font-size: 12px; color: #8a95a5; margin: 14px 0 6px; }
textarea, input { width: 100%; font: 15px/1.4 ui-monospace, monospace; background: #0e1116; color: #e6e9ef;
  border: 1px solid #2c3542; border-radius: 10px; padding: 10px; }
.save { width: 100%; margin-top: 18px; padding: 14px; border: 0; border-radius: 14px; background: #4f8cff;
  color: #0b1220; font-weight: 700; font-size: 16px; cursor: pointer; }
.save:disabled { opacity: .6; }
.cancel { width: 100%; margin-top: 10px; padding: 12px; background: none; border: 0; color: #8a95a5; }
#toast { position: fixed; top: 14px; left: 50%; transform: translateX(-50%); z-index: 20;
  max-width: 90vw; padding: 10px 16px; border-radius: 12px; font-size: 14px; display: none; }
#toast.ok { background: #10331c; color: #55d678; border: 1px solid #1f5b33; }
#toast.err { background: #3b1418; color: #ff7b84; border: 1px solid #6e222a; }
.hint { margin: 16px; color: #778394; font-size: 13px; }
#sheet h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: #8a95a5; margin: 18px 0 4px; }
.check { display: flex; align-items: center; gap: 10px; margin-top: 14px; font-size: 14px; cursor: pointer; }
.check input { width: auto; }
select { width: 100%; background: #0e1116; color: #e6e9ef; border: 1px solid #2c3542; border-radius: 10px; padding: 10px; font: 14px system-ui, sans-serif; }
#probe-list { max-height: 220px; overflow-y: auto; border: 1px solid #232a35; border-radius: 10px; padding: 4px 10px; margin-top: 8px; }
.pr { padding: 6px 0; border-bottom: 1px solid #232a35; font: 11px/1.5 ui-monospace, monospace; }
.pr:last-child { border-bottom: 0; }
.pr .p { color: #e6e9ef; word-break: break-all; }
.pr .t { color: #55c8d6; }
.pr .m { color: #778394; }
</style>
</head>
<body>
<header><h1>nginx access</h1><button class="gear" onclick="openScanner()">🛡 Probes</button><button class="gear" onclick="openGlobal()">⚙ Whitelist</button></header>
<div id="banners"></div>
<div id="list"></div>
<div id="sheet-back" onclick="closeSheet()"></div>
<div id="sheet"></div>
<div id="toast"></div>
<script>
const PROF = {
  'allow-all':     ['c-ok',  'Allow all', 'No restrictions'],
  'countries':     ['c-mid', 'Countries', 'Only listed countries + whitelisted IPs'],
  'whitelist-only':['c-warn','Whitelist', 'Only whitelisted IPs (global + per-domain)'],
  'block-all':     ['c-bad', 'Blocked',   '503 maintenance for everyone, even whitelisted IPs'],
};
let S = null, SEL = 'allow-all', CUR = null;

function el(html) { const d = document.createElement('div'); d.innerHTML = html.trim(); return d.firstElementChild; }
function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;'); }

async function load() {
  try {
    const r = await fetch('api/state');
    if (!r.ok) throw new Error(await r.text());
    S = await r.json();
  } catch (e) {
    document.getElementById('list').innerHTML = '<div class="hint">cannot reach the server: ' + escHtml(String(e)) + '</div>';
    return;
  }
  render();
}

function chip(p) { const c = PROF[p][0], l = PROF[p][1]; return '<span class="chip ' + c + '">' + l + '</span>'; }

function render() {
  const b = [];
  if (!S.http_bridge)
    b.push('<div class="banner info">nginx does not include <code>access-control/http.conf</code> yet — add it to the http context and reload.</div>');
  if (!S.geoip_available)
    b.push('<div class="banner warn">geoip2 module not detected — country profiles will be rejected until it is installed.</div>');
  document.getElementById('banners').innerHTML = b.join('');
  const list = document.getElementById('list');
  list.innerHTML = '';
  if (!S.domains.length) {
    list.innerHTML = '<div class="hint">No server blocks found — check AC_SITE_DIRS and make sure this tool can read them.</div>';
    return;
  }
  for (const d of S.domains) {
    const row = el('<div class="domain"><div class="name">' + escHtml(d.name) +
      (d.wired ? '' : '<small>not wired — server block lacks the server.conf include</small>') +
      '</div>' + chip(d.profile) + '</div>');
    row.onclick = () => openDomain(d.name);
    list.appendChild(row);
  }
}

function openDomain(name) {
  CUR = name;
  const d = S.domains.find(x => x.name === name) || { profile: 'allow-all', countries: [], whitelist: [] };
  SEL = d.profile;
  const opts = Object.entries(PROF).map(function(kv) {
    const k = kv[0], c = kv[1][0], l = kv[1][1], s = kv[1][2];
    return '<button class="opt' + (k === SEL ? ' sel' : '') + '" data-p="' + k + '">' +
      '<span class="dot"></span><span><b>' + l + '</b><span class="d">' + s + '</span></span></button>';
  }).join('');
  const sheet = document.getElementById('sheet');
  sheet.innerHTML =
    '<h2>' + escHtml(name) + '</h2>' +
    '<div class="sub">Blocked requests get a 503 maintenance response.' +
    (d.wired ? '' : ' &#9888; This server block has no <code>server.conf</code> include — changes will not take effect.') +
    '</div>' + opts +
    '<div id="cc-box" style="display:none"><label>Allowed countries — ISO 3166-1 alpha-2, comma separated</label>' +
    '<input id="cc" value="' + escHtml((d.countries || []).join(', ')) + '" placeholder="CH, DE"></div>' +
    '<div id="wl-box" style="display:none"><label>Per-domain whitelisted IPs — one per line</label>' +
    '<textarea id="wl" rows="3">' + escHtml((d.whitelist || []).join('\n')) + '</textarea></div>' +
    '<button class="save" onclick="saveDomain()">Save &amp; apply</button>' +
    '<button class="cancel" onclick="closeSheet()">Cancel</button>';
  sheet.querySelectorAll('.opt').forEach(function(o) {
    o.onclick = function() {
      SEL = o.dataset.p;
      sheet.querySelectorAll('.opt').forEach(function(x) { x.classList.toggle('sel', x === o); });
      boxes();
    };
  });
  boxes();
  sheet.classList.add('open');
  document.getElementById('sheet-back').classList.add('open');
}

function boxes() {
  document.getElementById('cc-box').style.display = SEL === 'countries' ? '' : 'none';
  document.getElementById('wl-box').style.display = (SEL === 'countries' || SEL === 'whitelist-only') ? '' : 'none';
}

async function saveDomain() {
  const btn = document.querySelector('#sheet .save');
  btn.disabled = true; btn.textContent = 'applying…';
  const body = {
    profile: SEL,
    countries: (document.getElementById('cc').value.match(/[A-Za-z]{2}/g) || []),
    whitelist: document.getElementById('wl').value.split(/[\s,;]+/).filter(Boolean),
  };
  try {
    const r = await fetch('api/domains/' + encodeURIComponent(CUR), {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (r.ok) {
      const j = await r.json();
      toast('applied — nginx reloaded' + (j.warning ? ' ⚠ ' + j.warning : ''), true);
      closeSheet(); load();
    } else {
      toast('✗ ' + await r.text(), false);
      btn.disabled = false; btn.textContent = 'Save & apply';
    }
  } catch (e) {
    toast('✗ ' + e, false);
    btn.disabled = false; btn.textContent = 'Save & apply';
  }
}

function openGlobal() {
  const sheet = document.getElementById('sheet');
  sheet.innerHTML =
    '<h2>Global whitelist</h2>' +
    '<div class="sub">IPs and CIDR ranges that always pass the <b>Countries</b> and <b>Whitelist</b> profiles. The <b>Blocked</b> profile ignores it.</div>' +
    '<label>One IP or CIDR per line</label>' +
    '<textarea id="gwl" rows="6">' + escHtml((S.global_whitelist || []).join('\n')) + '</textarea>' +
    '<button class="save" onclick="saveGlobal()">Save &amp; apply</button>' +
    '<button class="cancel" onclick="closeSheet()">Cancel</button>';
  sheet.classList.add('open');
  document.getElementById('sheet-back').classList.add('open');
}

async function saveGlobal() {
  const btn = document.querySelector('#sheet .save');
  btn.disabled = true; btn.textContent = 'applying…';
  const list = document.getElementById('gwl').value.split(/[\s,;]+/).filter(Boolean);
  try {
    const r = await fetch('api/global', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ whitelist: list }) });
    if (r.ok) { toast('applied — nginx reloaded', true); closeSheet(); load(); }
    else { toast('✗ ' + await r.text(), false); btn.disabled = false; btn.textContent = 'Save & apply'; }
  } catch (e) {
    toast('✗ ' + e, false);
    btn.disabled = false; btn.textContent = 'Save & apply';
  }
}

function openScanner() {
  const h = S.hotpath;
  const sheet = document.getElementById('sheet');
  sheet.innerHTML =
    '<h2>Scanner protection</h2>' +
    '<div class="sub">Hot paths are matched case-insensitively (regex) against the request URI. Hits are always logged below; when enabled they are also blocked. Only wired vhosts report probes.</div>' +
    '<h3>Recent probes</h3>' +
    '<div id="probe-stats" class="sub">loading…</div>' +
    '<div id="probe-list"></div>' +
    '<label class="check"><input type="checkbox" id="hp-on"' + (h.enabled ? ' checked' : '') + '> enabled — block matching requests</label>' +
    '<label>Action for blocked probes</label>' +
    '<select id="hp-action">' +
    '<option value="drop"' + (h.action === 'drop' ? ' selected' : '') + '>444 — drop connection without response</option>' +
    '<option value="not-found"' + (h.action === 'not-found' ? ' selected' : '') + '>404 — not found</option></select>' +
    '<label>Hot paths — one regex per line, matched on the request URI</label>' +
    '<textarea id="hp-pat" rows="7">' + escHtml(h.patterns.join('\n')) + '</textarea>' +
    '<button class="save" onclick="saveHotpath()">Save &amp; apply</button>' +
    '<button class="cancel" onclick="closeSheet()">Cancel</button>';
  sheet.classList.add('open');
  document.getElementById('sheet-back').classList.add('open');
  loadProbes();
}

async function loadProbes() {
  const stats = document.getElementById('probe-stats');
  const list = document.getElementById('probe-list');
  if (!stats || !list) return;
  try {
    const j = await (await fetch('api/probes')).json();
    const p = j.entries || [];
    if (!p.length) { stats.textContent = 'No probes logged yet.'; list.innerHTML = ''; return; }
    const byHost = {};
    for (const e of p) byHost[e.host] = (byHost[e.host] || 0) + 1;
    const top = Object.entries(byHost).sort((a, b) => b[1] - a[1]).slice(0, 6)
      .map(kv => escHtml(kv[0]) + ' ×' + kv[1]).join(', ');
    stats.innerHTML = '<b>' + p.length + '</b> recent probes — ' + top;
    list.innerHTML = p.slice(0, 50).map(e =>
      '<div class="pr"><div class="p">' + escHtml(e.request) + '</div>' +
      '<div><span class="t">' + escHtml(e.time.slice(5, 16).replace('T', ' ')) + '</span> · <span class="m">' +
      escHtml(e.host) + ' · ' + escHtml(e.ip) + ' · ' + escHtml(e.status) + '</span></div></div>').join('');
  } catch (e) {
    stats.textContent = 'cannot read the probe log: ' + e;
  }
}

async function saveHotpath() {
  const btn = document.querySelector('#sheet .save');
  btn.disabled = true; btn.textContent = 'applying…';
  const body = {
    enabled: document.getElementById('hp-on').checked,
    action: document.getElementById('hp-action').value,
    patterns: document.getElementById('hp-pat').value.split('\n'),
  };
  try {
    const r = await fetch('api/hotpath', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (r.ok) { toast('applied — nginx reloaded', true); closeSheet(); load(); }
    else { toast('✗ ' + await r.text(), false); btn.disabled = false; btn.textContent = 'Save & apply'; }
  } catch (e) {
    toast('✗ ' + e, false);
    btn.disabled = false; btn.textContent = 'Save & apply';
  }
}

function closeSheet() {
  document.getElementById('sheet').classList.remove('open');
  document.getElementById('sheet-back').classList.remove('open');
}

function toast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = ok ? 'ok' : 'err';
  t.style.display = 'block';
  clearTimeout(t._h);
  t._h = setTimeout(function() { t.style.display = 'none'; }, 6000);
}

load();
</script>
</body>
</html>
"##;

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let ctx = Ctx::from_env();

    // Prepare the managed directory so nginx includes never dangle.
    if let Err(e) = fs::create_dir_all(&ctx.dir) {
        eprintln!("cannot create {}: {e}", ctx.dir.display());
        std::process::exit(1);
    }
    let state = match load_state(&ctx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if !state_path(&ctx).exists() {
        if let Ok(json) = serde_json::to_string_pretty(&state) {
            let _ = atomic_write(&state_path(&ctx), &json);
        }
    }
    // server.conf and http.conf are written as a consistent pair; if rendering
    // fails we keep the previous pair so `nginx -t` keeps passing.
    match render_http(&state, &ctx) {
        Ok(h) => {
            let server = render_server(&ctx);
            if let Err(e) = atomic_write(&ctx.dir.join("server.conf"), &server) {
                eprintln!("{e}");
            }
            if let Err(e) = atomic_write(&ctx.dir.join("http.conf"), &h) {
                eprintln!("{e}");
            }
        }
        Err(e) => eprintln!("keeping previous config pair: {e}"),
    }

    // Prefix every route with the public path and inject it into the UI as a
    // <base> tag, so the embedded page works at /proxy/ (or anywhere else).
    let ui_html = INDEX_HTML.replace("__AC_PREFIX__", &ctx.prefix);
    let p = ctx.prefix.as_str();
    let index_html = ui_html.clone();
    let app = Router::new()
        .route(
            p,
            get(move || {
                let h = index_html.clone();
                async move { Html(h) }
            }),
        )
        .route(&format!("{p}api/state"), get(api_state))
        .route(&format!("{p}api/test"), post(api_test))
        .route(&format!("{p}api/global"), put(api_set_global))
        .route(&format!("{p}api/hotpath"), put(api_set_hotpath))
        .route(&format!("{p}api/probes"), get(api_probes))
        .route(
            &format!("{p}api/domains/{{domain}}"),
            put(api_set_domain).delete(api_delete_domain),
        )
        .with_state(ctx.clone());

    let listener = tokio::net::TcpListener::bind(&ctx.listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("cannot bind {}: {e}", ctx.listen);
            std::process::exit(1);
        });
    eprintln!("ac-control listening on http://{}{p}", ctx.listen);
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> Ctx {
        Ctx {
            dir: PathBuf::from("/tmp/ac-test"),
            site_dirs: vec![PathBuf::from("/tmp/ac-test-sites")],
            geoip_db: PathBuf::from("/tmp/GeoLite2-Country.mmdb"),
            nginx_bin: "nginx".into(),
            reload_cmd: vec!["true".into()],
            listen: "127.0.0.1:0".into(),
            probe_log: PathBuf::from("/tmp/ac-probes.log"),
            prefix: "/".into(),
        }
    }

    #[test]
    fn prefix_normalization() {
        assert_eq!(normalize_prefix("proxy/"), "/proxy/");
        assert_eq!(normalize_prefix("/proxy"), "/proxy/");
        assert_eq!(normalize_prefix("/proxy/"), "/proxy/");
        assert_eq!(normalize_prefix("  /proxy  "), "/proxy/");
        assert_eq!(normalize_prefix(""), "/");
        assert_eq!(normalize_prefix("/"), "/");
    }

    #[test]
    fn server_names_parsed_and_comment_ignored() {
        let conf = "server {\n listen 80; server_name a.example one.example *.wild.example;\n}\n\
                    # server_name commented.example;\n\
                    server { server_name_names not.a.name; server_name b.example; }";
        let names = extract_server_names(&strip_comments(conf));
        assert_eq!(
            names,
            vec!["a.example", "one.example", "*.wild.example", "b.example"]
        );
    }

    #[test]
    fn default_render_has_no_geoip_and_allows_all() {
        let http = render_http(&State::default(), &test_ctx()).unwrap();
        assert!(http.contains("map $host $ac_profile"));
        assert!(!http.contains("geoip2"));
        assert!(http.contains("default \"allow-all\";"));
        assert!(http.contains("geo $ac_country { default 0; }"));
    }

    #[test]
    fn hotpath_maps_reflect_state() {
        let ctx = test_ctx();
        let mut st = AppState::default();
        assert!(st.hotpath.enabled);
        let http = render_http(&st, &ctx).unwrap();
        assert!(http.contains("log_format ac_probe"));
        assert!(http.contains("~*(?:"));
        assert!(http.contains(r"\.env"));
        assert!(http.contains("map $ac_hot_hit $ac_hot_drop {\n    default 0;\n    1 1;\n}"));
        assert!(http.contains("map $ac_hot_hit $ac_hot_404 {\n    default 0;\n}"));
        st.hotpath.enabled = false;
        let http = render_http(&st, &ctx).unwrap();
        assert!(http.contains("map $ac_hot_hit $ac_hot_drop {\n    default 0;\n}"));
    }

    #[test]
    fn domain_validation() {
        assert!(valid_domain("shop.example.com"));
        assert!(valid_domain("*.example.com"));
        assert!(!valid_domain("evil\";name"));
        assert!(!valid_domain(""));
        assert!(!valid_domain("~^regex"));
        assert!(valid_ip_or_cidr("203.0.113.4"));
        assert!(valid_ip_or_cidr("203.0.113.0/24"));
        assert!(valid_ip_or_cidr("2001:db8::/32"));
        assert!(!valid_ip_or_cidr("203.0.113.0/40"));
        assert!(!valid_ip_or_cidr("not-an-ip"));
    }
}

# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`waf_ac_control` ("ac-control") is a single-binary Rust web service that runs
**on the nginx reverse-proxy server itself** and lets the owner manage
per-domain access profiles and scanner protection from a phone.

Request flow:

```
phone browser -> nginx (TLS + auth_basic at location /proxy/)
             -> 127.0.0.1:8080 (this tool)
```

The tool has **no authentication of its own** and must only ever listen on
localhost. Auth is delegated to the nginx `location /proxy/` block (see
README.md).

## Repo layout

- `src/main.rs` — the **entire application in one file, by design**: config
  from env, state model, nginx config generation, vhost scanning, axum API,
  embedded mobile UI (`const INDEX_HTML`), unit tests. Do not split it into
  modules unless a change becomes genuinely unmanageable.
- `Cargo.toml` — Rust edition 2024, deps: axum 0.8, tokio, serde, serde_json.
  Keep dependencies minimal; no async runtime extras, no template engines.
- `README.md` — the nginx wiring snippet for the reverse proxy.

## What the tool does at runtime

It owns exactly three files (nothing else — **all other nginx config is
ansible-managed and must never be written by this tool**):

- `/etc/nginx/access-control/state.json` — persisted state, source of truth
- `/etc/nginx/access-control/http.conf` — generated `map`/`geo` blocks,
  included once in nginx's http context
- `/etc/nginx/access-control/server.conf` — a fixed snippet included once in
  every `server {}` block: the `if ($ac_*) { return …; }` enforcement lines
  plus the probe `access_log`

Domain profiles (per `server_name`):

- `allow-all` — no restriction
- `countries` — only listed ISO 3166-1 alpha-2 countries + whitelisted IPs
  (needs the nginx geoip2 module + a GeoLite2-Country mmdb)
- `whitelist-only` — only global (IPs/CIDR) + per-domain (exact IPs) whitelist
- `block-all` — 503 maintenance for **everyone, whitelists included** (kill
  switch; do not "fix" this to respect whitelists)

Scanner protection ("hot paths"): configurable regex fragments matched
case-insensitively (single `~*(?:p1|p2|…)` alternation) against `$uri` in the
map `$ac_hot_hit`. Matching requests are always logged to
`/var/log/nginx/ac-probes.log` (`log_format ac_probe`, pipe-separated) and,
when enabled, blocked with 444 (drop) or 404 via `$ac_hot_drop` /
`$ac_hot_404`.

Every mutation goes through `apply()`: render `http.conf` → atomic write →
`nginx -t` → **rollback both files on failure** → `systemctl reload nginx`.
This rollback invariant is the core safety property of the tool: the UI can
never leave nginx with a rejected config.

`scan_vhosts()` reads nginx.conf + site dirs to list `server_name` values and
detects "wired" vhosts (those containing the `server.conf` include) and the
http-context bridge.

The web UI is embedded as `INDEX_HTML` with a `<base href="__AC_PREFIX__">`
tag injected at startup; all JS fetch calls are **relative** so the UI works
under any path prefix (`AC_PREFIX`, default `/proxy/`).

## API (all under the prefix)

- `GET  api/state` — domains, profiles, whitelist, hotpath config, wiring status
- `PUT  api/domains/{domain}` — set profile + countries + per-domain whitelist
- `DELETE api/domains/{domain}` — reset to allow-all
- `PUT  api/global` — global whitelist (IPs/CIDR)
- `PUT  api/hotpath` — scanner protection: enabled, action, patterns
- `GET  api/probes` — recent probe-log entries (newest first, max 150)
- `POST api/test` — run `nginx -t`, return output

## Env vars (all optional)

| Var | Default |
|---|---|
| `AC_LISTEN` | `127.0.0.1:8080` |
| `AC_PREFIX` | `/proxy/` |
| `AC_DIR` | `/etc/nginx/access-control` |
| `AC_SITE_DIRS` | `/etc/nginx/sites-enabled,/etc/nginx/conf.d` |
| `AC_GEOIP_DB` | `/usr/share/GeoIP/GeoLite2-Country.mmdb` |
| `AC_NGINX_BIN` | `nginx` |
| `AC_RELOAD_CMD` | `systemctl reload nginx` |
| `AC_PROBE_LOG` | `/var/log/nginx/ac-probes.log` |

## Build & test

```bash
cargo build --release
cargo test
```

No CI yet. Tests are unit tests inside `src/main.rs` (`mod tests`): config
rendering assertions, `server_name` parsing, input validation, prefix
normalization. When changing `render_http`/`render_server`, extend those
tests rather than adding new test files.

## Critical invariants — do not break

1. **Pair consistency**: `server.conf` and `http.conf` must always be written
   together (see `main()` startup and `apply()`). Any variable referenced in
   `server.conf` must be unconditionally defined in `http.conf` — nginx fails
   `-t` on unknown variables.
2. **Stub disabled features**: e.g. without country profiles,
   `geo $ac_country { default 0; }` keeps `$ac_country` defined. Apply the
   same pattern for any new `$ac_*` variable.
3. **Emission safety**: generated nginx values are quoted strings; user input
   is validated before it reaches the config (hot-path patterns must not
   contain `"`, max 200 chars, max 100 patterns; countries are exactly two
   ASCII letters; domains are charset-checked; IPs parsed with `IpAddr`).
4. **state.json backward compatibility**: every new struct field needs
   `#[serde(default)]`; old state files must keep loading.
5. **Naming**: the app state struct is `AppState` (renamed from `State` to
   avoid clashing with axum's `State` extractor); std `Path` is imported as
   `FsPath` for the same reason.
6. **Wire format consistency**: `Profile` and `HotAction` serialize as
   kebab-case (`allow-all`, `not-found`, …) — the embedded JS and the
   generated nginx decision-map keys must match exactly.
7. `INDEX_HTML` is a Rust raw string `r##"…"##`: the sequence `"##` must
   never appear inside the HTML/JS.
8. Default `AC_LISTEN` stays on localhost. The tool is root-only config
   management behind nginx auth; it must not gain its own public listener.

## Deployment facts (for docs/context, not for the agent to perform)

- Runs as a systemd service as root (needs to write `/etc/nginx/access-control`
  and reload nginx).
- Ansible owns nginx config; wiring is exactly two include lines (http context
  + every `server {}`), added once in the ansible templates.
- nginx vhost exposes the UI at `https://{fqdn}/proxy/` with `auth_basic`
  scoped **inside** the location; `proxy_pass http://127.0.0.1:8080;` without
  trailing slash so the prefix is passed through.
- Deploying a new binary: copy it, `systemctl restart waf_ac_control` (rewrites
  the config pair), then reload nginx once.

## Known issues

- `mod tests` currently does not compile: the test
  `default_render_has_no_geoip_and_allows_all` still calls
  `State::default()` from before the `AppState` rename — change it to
  `AppState::default()` (`cargo build` is unaffected; only `cargo test` is).
- The `countries` profile requires the nginx geoip2 module
  (`nginx -V` must list it) and a GeoLite2-Country mmdb on disk;
  `render_http` returns a descriptive error otherwise — keep that behavior.
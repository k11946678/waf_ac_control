# waf_ac_control

## nginx config

```
server {
    listen 443 ssl;
    server_name {fqdn};
    include /etc/nginx/access-control/server.conf;

    location = /proxy { return 301 /proxy/; }

    location /proxy/ {
        auth_basic "nginx admin";
        auth_basic_user_file /etc/nginx/htpasswd/ac-admin;
        proxy_pass http://127.0.0.1:8080;   # no trailing slash -> /proxy/ prefix is passed through
        proxy_set_header Host $host;
    }
}
```

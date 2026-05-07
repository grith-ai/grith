# Reverse Proxy and TLS Deployment

This guide covers secure network exposure of the grith API/dashboard.

## Default posture

- Default bind: `127.0.0.1:3141`
- Default transport: HTTP (local only)
- For non-localhost exposure, use one of:
  - Native TLS via `[server.tls]`
  - TLS termination at a reverse proxy (nginx or Caddy)

## Native TLS (direct)

```toml
[server]
enabled = true
host = "0.0.0.0"
port = 3141

[server.tls]
cert_path = "/etc/grith/tls/fullchain.pem"
key_path = "/etc/grith/tls/privkey.pem"
```

## Reverse proxy: nginx

```nginx
server {
    listen 443 ssl http2;
    server_name grith.example.com;

    ssl_certificate     /etc/letsencrypt/live/grith.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/grith.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3141;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Reverse proxy: Caddy

```caddyfile
grith.example.com {
    reverse_proxy 127.0.0.1:3141
}
```

## Recommended auth hardening for network exposure

```toml
[auth]
localhost_only = false
require_api_key = true
api_key = "replace-with-strong-random-secret"
```

- Never expose non-localhost HTTP without TLS.
- Keep grith bound to localhost when behind a reverse proxy.

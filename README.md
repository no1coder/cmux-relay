# cmux-relay

WebSocket relay server for [cmux](https://github.com/manaflow-ai/cmux) — enables remote terminal access from iOS to Mac.

## Architecture

```
Mac (cmux) ←→ WebSocket ←→ cmux-relay ←→ WebSocket ←→ iPhone (cmux-mobile)
```

- **QR code pairing** with one-time tokens (5-minute expiry)
- **HMAC-SHA256 authentication** with server-issued nonce (replay protection)
- **Message buffering** with ring buffer for disconnect recovery
- **APNs push notifications** for offline scenarios (optional)
- **SQLite** for persistent storage (WAL mode)
- **TLS 1.3** support for production deployment

## Quick Start

### Docker (recommended)

```bash
docker compose up -d
```

### Build from source

```bash
go build -o cmux-relay .
./cmux-relay -addr :8443 -db cmux-relay.db
```

### With TLS

```bash
./cmux-relay -addr :8443 -db cmux-relay.db -cert cert.pem -key key.pem
```

## Deployment with Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name relay.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/pair/init` | Mac requests a pairing token |
| POST | `/api/pair/confirm` | iPhone confirms pairing |
| GET | `/api/pair/check/{device_id}` | Mac polls for pairing result |
| DELETE | `/api/pair/{phone_id}` | Unpair devices |
| POST | `/api/push/token` | Register APNs push token |
| WS | `/ws/device/{device_id}` | Mac WebSocket connection |
| WS | `/ws/phone/{phone_id}` | iPhone WebSocket connection |
| GET | `/health` | Health check |

## Configuration

All configuration is via command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8443` | Listen address |
| `-db` | `cmux-relay.db` | SQLite database path |
| `-cert` | (none) | TLS certificate file |
| `-key` | (none) | TLS private key file |

## License

MIT

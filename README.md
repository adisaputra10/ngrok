# GoTunnel

Self-hosted tunnel service like ngrok/Cloudflare Tunnel, built in Go. Expose local services to the internet with automatic HTTPS, a web dashboard, multi-user support, and request inspection.

## Features

- **Web Dashboard** — Register, login, manage tunnels, view request logs
- **Multi-User** — Each user gets their own account, auth token, and tunnels
- **Custom Subdomains** — Reserve subdomains for persistent URLs
- **Request Inspection** — View real-time HTTP request logs with status codes and duration
- **WebSocket Tunnels** — Efficient tunnel protocol over WebSocket (no SSH dependency)
- **Single Binary** — Server and client are single Go binaries, zero runtime dependencies
- **Docker Ready** — Deploy with `docker compose up` in minutes
- **Automatic HTTPS** — Use with Caddy for auto TLS, or bring your own certificates
- **Cross-Platform Client** — Works on Linux, macOS, and Windows

## Architecture

```
┌─────────────┐          ┌──────────────────────────────────────┐
│   Client     │ WebSocket│         GoTunnel Server               │
│  (gotunnel)  │─────────▶│                                      │
│              │          │  ┌──────────┐   ┌─────────────────┐  │
│ localhost:   │◀─────────│  │ Tunnel   │   │  Web Dashboard  │  │
│   3000       │  HTTP    │  │ Manager  │   │  (port 8080)    │  │
└─────────────┘  Proxy   │  └────┬─────┘   └─────────────────┘  │
                          │       │                               │
                          │  ┌────▼─────┐   ┌─────────────────┐  │
Internet ───────────────▶ │  │  Reverse  │   │    SQLite DB    │  │
  *.tunnel.example.com    │  │  Proxy    │   │  (users,tunnels)│  │
                          │  │ (port 80) │   └─────────────────┘  │
                          │  └──────────┘                         │
                          └──────────────────────────────────────┘
```

**How it works:**
1. Client connects to server via WebSocket and authenticates
2. Server registers the subdomain and routes incoming HTTP traffic
3. When a request arrives for `myapp.tunnel.example.com`, the server forwards it through the WebSocket to the client
4. Client proxies the request to the local service and sends the response back
5. Server returns the response to the original requester

## Quick Start

### 1. Deploy the Server

```bash
# Clone the repo
git clone <repo-url>
cd gotunnel

# Configure
cp .env.example .env
# Edit .env — set GOTUNNEL_DOMAIN and GOTUNNEL_SECRET

# Run with Docker
docker compose up -d

# Or build and run directly
make build
./bin/gotunnel-server
```

### 2. Set Up DNS

Add a wildcard A record pointing to your server:

| Type | Name | Value |
|------|------|-------|
| A    | *    | `<your-server-ip>` |

### 3. Create an Account

Open `http://your-server:8080` in your browser and register an account.

### 4. Install the Client

```bash
# Download the binary (or build from source)
make build-client
sudo mv bin/gotunnel /usr/local/bin/

# Authenticate
gotunnel auth <your-auth-token> --server your-server:8080
```

You can find your auth token in the Dashboard → Setup & Install page.

### 5. Create a Tunnel

```bash
# Expose localhost:3000 as https://myapp.tunnel.example.com
gotunnel myapp 3000

# Expose an API
gotunnel api 8080

# With explicit server and token
gotunnel myapp 3000 --server tunnel.example.com:8080 --token gt_abc123...
```

## Dashboard

The web dashboard provides:

- **Dashboard** — Overview with stats, active connections, and tunnel list
- **Tunnels** — Manage tunnels, reserve subdomains, view status
- **Setup & Install** — Client installation instructions with your auth token
- **Settings** — Change password, regenerate auth token
- **Request Logs** — Per-tunnel HTTP request logs with method, path, status, and timing

## Server Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GOTUNNEL_DOMAIN` | `tunnel.localhost` | Base domain for tunnels |
| `GOTUNNEL_ADMIN_PORT` | `8080` | Admin dashboard port |
| `GOTUNNEL_PROXY_PORT` | `80` | Public tunnel traffic port |
| `GOTUNNEL_SECRET` | (required) | Secret key for sessions |
| `GOTUNNEL_DB_PATH` | `./data/gotunnel.db` | SQLite database path |
| `GOTUNNEL_ALLOW_REGISTRATION` | `true` | Enable public registration |
| `GOTUNNEL_TLS_CERT` | | TLS certificate path |
| `GOTUNNEL_TLS_KEY` | | TLS private key path |

## Client Configuration

The client stores config in `~/.gotunnel/config.json`:

```json
{
  "server_url": "tunnel.example.com:8080",
  "auth_token": "gt_abc123..."
}
```

Commands:
```bash
gotunnel auth <token>           # Save auth token
gotunnel auth <token> --server <url>  # Save token and server
gotunnel config                 # Show current config
gotunnel myapp 3000             # Create tunnel
gotunnel --help                 # Show help
```

## Production Deployment with HTTPS

For production, use Caddy as a reverse proxy for automatic HTTPS:

1. Edit `Caddyfile` with your domain
2. Uncomment the caddy service in `docker-compose.yml`
3. Set DNS wildcard record
4. Run `docker compose up -d`

Caddy will automatically provision TLS certificates for your domain and all tunnel subdomains.

## Building from Source

```bash
# Prerequisites: Go 1.22+
make deps      # Download dependencies
make build     # Build server & client
make release   # Build for all platforms
```

## Development

```bash
# Run server in dev mode
make run-server

# Run client
go run ./cmd/client myapp 3000 --server localhost:8080 --token <token>
```

## Tech Stack

- **Go** — Server and client
- **WebSocket** — Tunnel protocol (gorilla/websocket)
- **SQLite** — Database (modernc.org/sqlite, pure Go)
- **Tailwind CSS** — Dashboard UI (via CDN)
- **html/template** — Server-side rendering
- **embed** — Templates and static files embedded in binary

## License

MIT

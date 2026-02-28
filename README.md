# Demolocal

Self-hosted tunnel service for **demolocal.online** — expose local services to the internet with automatic HTTPS, built in Go. Like ngrok, but yours.

## Features

- **Web Dashboard** — Register, login, manage tunnels, view request logs
- **Multi-User** — Each user gets their own account, auth token, and tunnels
- **Custom Subdomains** — Reserve subdomains for persistent URLs at `*.demolocal.online`
- **Request Inspection** — Real-time HTTP request logs with status codes and timing
- **WebSocket Tunnels** — Efficient tunnel protocol over WebSocket (no SSH needed)
- **Single Binary** — Server and client are standalone Go binaries, zero runtime dependencies
- **Docker Ready** — Deploy with `docker compose up` in minutes
- **Automatic HTTPS** — ZeroSSL/Let's Encrypt auto-TLS via ACME
- **Cross-Platform Client** — Linux, macOS, and Windows binaries
- **Google OAuth** — Sign in with Google
- **Extra Proxies** — Route custom subdomains (e.g. `ollama.demolocal.online`) to internal services

## Architecture

```
┌─────────────┐          ┌──────────────────────────────────────┐
│   Client     │ WebSocket│         Demolocal Server              │
│  (demolocal) │─────────▶│                                      │
│              │          │  ┌──────────┐   ┌─────────────────┐  │
│ localhost:   │◀─────────│  │ Tunnel   │   │  Web Dashboard  │  │
│   3000       │  HTTP    │  │ Manager  │   │  (port 8080)    │  │
└─────────────┘  Proxy   │  └────┬─────┘   └─────────────────┘  │
                          │       │                               │
                          │  ┌────▼─────┐   ┌─────────────────┐  │
Internet ───────────────▶ │  │  Reverse  │   │    SQLite DB    │  │
  *.demolocal.online      │  │  Proxy    │   │  (users,tunnels)│  │
                          │  │ (port 443)│   └─────────────────┘  │
                          │  └──────────┘                         │
                          └──────────────────────────────────────┘
```

**How it works:**
1. Client connects to server via WebSocket and authenticates
2. Server registers the subdomain and routes incoming HTTPS traffic
3. When a request arrives for `myapp.demolocal.online`, the server forwards it through the WebSocket to the client
4. Client proxies the request to the local service and sends the response back
5. Server returns the response to the original requester

## Quick Start

### 1. Deploy the Server

```bash
# Clone the repo
git clone https://github.com/adisaputra10/ngrok
cd ngrok

# Configure
cp .env.example .env
# Edit .env — set GOTUNNEL_SECRET and other values

# Run with Docker (recommended)
docker compose up -d

# Or build and run directly
make build
./bin/gotunnel-server
```

### 2. Set Up DNS

Add a wildcard A record pointing to your server:

| Type | Name | Value |
|------|------|-------|
| A    | `*`  | `<your-server-ip>` |
| A    | `@`  | `<your-server-ip>` |

### 3. Create an Account

Open `https://demolocal.online` in your browser and register, or use Google OAuth.

### 4. Install the Client

**Linux (amd64)**
```bash
curl -fsSL https://demolocal.online/download/demolocal-linux-amd64 -o demolocal
chmod +x demolocal
sudo mv demolocal /usr/local/bin/
```

**Linux (ARM64 — Raspberry Pi, etc.)**
```bash
curl -fsSL https://demolocal.online/download/demolocal-linux-arm64 -o demolocal
chmod +x demolocal
sudo mv demolocal /usr/local/bin/
```

**macOS (Apple Silicon)**
```bash
curl -fsSL https://demolocal.online/download/demolocal-darwin-arm64 -o demolocal
chmod +x demolocal
sudo mv demolocal /usr/local/bin/
```

**macOS (Intel)**
```bash
curl -fsSL https://demolocal.online/download/demolocal-darwin-amd64 -o demolocal
chmod +x demolocal
sudo mv demolocal /usr/local/bin/
```

**Windows (PowerShell)**
```powershell
Invoke-WebRequest -Uri "https://demolocal.online/download/demolocal-windows-amd64.exe" -OutFile "demolocal.exe"
```

### 5. Authenticate

```bash
demolocal auth <your-auth-token> --server demolocal.online:8080
```

Find your auth token on the **Dashboard → Setup & Install** page.

### 6. Create a Tunnel

```bash
# Expose localhost:3000 → https://myapp.demolocal.online
demolocal myapp 3000

# Expose an API
demolocal api 8080

# With explicit server and token
demolocal myapp 3000 --server demolocal.online:8080 --token gt_abc123...
```

## CLI Reference

```
demolocal v1.0.0 — Expose local services to the internet

Usage:
  demolocal <subdomain> <port> [options]
  demolocal auth <token>                  Save auth token
  demolocal config                        Show current config

Options:
  --server <url>    Server URL (e.g., demolocal.online:8080)
  --token <token>   Auth token (overrides saved config)
  --version, -v     Show version
  --help, -h        Show help

Examples:
  demolocal myapp 3000                    https://myapp.demolocal.online → localhost:3000
  demolocal api 8080 --server demolocal.online:8080 --token gt_abc123...
```

Config is stored at `~/.demolocal/config.json`:
```json
{
  "server_url": "demolocal.online:8080",
  "auth_token": "gt_abc123..."
}
```

## Server Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GOTUNNEL_DOMAIN` | `demolocal.online` | Base domain for tunnels |
| `GOTUNNEL_ADMIN_PORT` | `8080` | Admin dashboard port |
| `GOTUNNEL_PROXY_PORT` | `80` | HTTP tunnel traffic port |
| `GOTUNNEL_SECRET` | (required) | Secret key for sessions |
| `GOTUNNEL_DB_TYPE` | `sqlite` | Database type (`sqlite` or `mysql`) |
| `GOTUNNEL_SQLITE_DB_PATH` | `./data/gotunnel.db` | SQLite database path |
| `GOTUNNEL_ALLOW_REGISTRATION` | `true` | Enable public registration |
| `GOTUNNEL_AUTO_TLS` | `false` | Enable ZeroSSL/Let's Encrypt auto-TLS |
| `GOTUNNEL_AUTO_TLS_EMAIL` | | Email for ACME registration |
| `GOTUNNEL_AUTO_TLS_DIR` | `./data/certs` | Certificate cache directory |
| `GOTUNNEL_ZEROSSL_API_KEY` | | ZeroSSL API key for EAB credentials |
| `GOTUNNEL_EXTRA_PROXIES` | | Extra subdomain→upstream mappings (see below) |
| `GOOGLE_CLIENT_ID` | | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | | Google OAuth client secret |
| `GOOGLE_REDIRECT_URL` | | Google OAuth redirect URL |

### Extra Proxies

Route specific subdomains directly to internal services without a tunnel client:

```env
GOTUNNEL_EXTRA_PROXIES=ollama.demolocal.online=http://10.11.0.9:11434,grafana.demolocal.online=http://localhost:3000
```

## Dashboard

- **Dashboard** — Stats, active connections, tunnel list
- **Tunnels** — Manage tunnels, reserve subdomains
- **Setup & Install** — Client install instructions with your auth token pre-filled
- **Settings** — Change password, regenerate auth token
- **Request Logs** — Per-tunnel HTTP logs with method, path, status, and timing

## Docker Deployment

```bash
docker compose up -d          # Start
docker compose logs -f        # Tail logs
docker compose down           # Stop
docker compose build --no-cache  # Rebuild (after code changes)
```

The Docker image cross-compiles all client binaries during build — no pre-built binaries needed in the repo.

Data is persisted in the `gotunnel_data` Docker volume (contains SQLite DB and TLS certs).

## Building from Source

```bash
# Prerequisites: Go 1.22+
make deps           # Download dependencies
make build          # Build server & client (bin/)
make release-client # Cross-compile client for all platforms → downloads/
make release-server # Build Linux server binaries → bin/
```

## Tech Stack

- **Go 1.22** — Server and client
- **gorilla/websocket** — Tunnel protocol
- **modernc.org/sqlite** — Pure-Go SQLite (no CGO)
- **golang.org/x/crypto/acme/autocert** — Auto-TLS (ZeroSSL / Let's Encrypt)
- **Tailwind CSS** — Dashboard UI (CDN)
- **html/template** + **embed** — Server-side rendering, assets embedded in binary

## License

MIT


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
  *.demolocal.online      │  │  Proxy    │   │  (users,tunnels)│  │
                          │  │ (port 80) │   └─────────────────┘  │
                          │  └──────────┘                         │
                          └──────────────────────────────────────┘
```

**How it works:**
1. Client connects to server via WebSocket and authenticates
2. Server registers the subdomain and routes incoming HTTP traffic
3. When a request arrives for `myapp.demolocal.online`, the server forwards it through the WebSocket to the client
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
# Expose localhost:3000 as https://myapp.demolocal.online
gotunnel myapp 3000

# Expose an API
gotunnel api 8080

# With explicit server and token
gotunnel myapp 3000 --server demolocal.online:8080 --token gt_abc123...
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
| `GOTUNNEL_DOMAIN` | `demolocal.online` | Base domain for tunnels |
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
  "server_url": "demolocal.online:8080",
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

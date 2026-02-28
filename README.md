# Demolocal

Self-hosted tunnel service for **demolocal.online** — expose local services to the internet with automatic HTTPS, built in Go. Like ngrok, but yours.

## Features

- **Web Dashboard** — Register, login, manage tunnels, view request logs
- **Multi-User** — Each user gets their own account, auth token, and tunnels
- **Custom Subdomains** — Reserve subdomains for persistent URLs at `*.demolocal.online`
- **Request Inspection** — Real-time HTTP request logs with status codes and timing
- **WebSocket Tunnels** — Secure WSS tunnels over port 443 (firewall-friendly)
- **Single Binary** — Server and client are standalone Go binaries, zero runtime dependencies
- **Docker Ready** — Pre-built client binaries available for download
- **Automatic HTTPS** — ZeroSSL/Let's Encrypt auto-TLS via ACME
- **Cross-Platform Client** — Linux (amd64/arm64), macOS (Intel/Silicon), Windows binaries
- **Google OAuth** — Sign in with Google
- **Extra Proxies** — Route custom subdomains to internal services

## Architecture

```
┌──────────────────┐          ┌──────────────────────────────────────┐
│   Client         │ WSS/TLS  │         Demolocal Server              │
│  (demolocal)     │─────────▶│                                      │
│  localhost:3000  │Port 443  │  ┌──────────┐   ┌─────────────────┐  │
│                  │◀─────────│  │ Tunnel   │   │  Web Dashboard  │  │
│                  │  Tunnel  │  │ Manager  │   │  (port 8080)    │  │
└──────────────────┘  Proxy   │  └────┬─────┘   └─────────────────┘  │
                                      │                               │
                          ┌───────────▼──────┐  ┌─────────────────┐  │
                          │  Reverse Proxy   │  │    SQLite DB    │  │
                          │  (port 443 HTTPS)│  │  (users,tunnels)│  │
                          │                  │  └─────────────────┘  │
                          │ *.demolocal.online                      │
                          └──────────────────┘                         │

 Internet
    │ HTTPS
    ▼
 myapp.demolocal.online ──▶ [Server:443] ──▶ [WSS Tunnel] ──▶ localhost:3000
```

**How it works:**
1. Client connects to server via **WSS (TLS)** on **port 443** and authenticates
2. Server registers the subdomain and routes incoming HTTPS traffic
3. When a request arrives for `myapp.demolocal.online`, server forwards it through the tunnel to the client
4. Client proxies the request to the local service (e.g. localhost:3000)
5. Server returns the response to the original requester

## Quick Start

### 1. Deploy the Server

```bash
# Clone the repo
git clone https://github.com/adisaputra10/ngrok
cd ngrok

# Configure
cp .env.example .env
# Edit .env — set GOTUNNEL_SECRET and optional settings

# Run with Docker (recommended)
docker compose up -d

# Or build and run directly
make build
./bin/gotunnel-server
```

### 2. Set Up DNS

Add wildcard A records pointing to your server:

| Type | Name | Value |
|------|------|-------|
| A    | `*`  | `<your-server-ip>` |
| A    | `@`  | `<your-server-ip>` |

### 3. Create an Account

Open `https://demolocal.online` in your browser and register, or use Google OAuth.

### 4. Download & Install Client

The client is **pre-configured with `demolocal.online`** — choose your platform:

**Linux (amd64)**
```bash
curl -fsSL https://demolocal.online/download/demolocal-linux-amd64 -o demolocal
chmod +x demolocal
sudo mv demolocal /usr/local/bin/
```

**Linux (ARM64 — Raspberry Pi, Jetson)**
```bash
curl -fsSL https://demolocal.online/download/demolocal-linux-arm64 -o demolocal
chmod +x demolocal
sudo mv demolocal /usr/local/bin/
```

**macOS (Apple Silicon M1/M2/M3)**
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

Or build from source:
```bash
go install github.com/adisaputra10/ngrok/cmd/client@latest
```

### 5. Authenticate

```bash
demolocal auth <your-auth-token>
# ✓ Auth token saved
#   Config: ~/.demolocal/config.json
#   Server: demolocal.online  (connects via wss:// on port 443)
```

Get your token at: **https://demolocal.online/dashboard/install**

### 6. Start Tunneling

```bash
# One command — works immediately
demolocal myapp 3000
# Connecting to demolocal.online (wss://demolocal.online)...
# Session Status:  online
# Forwarding:      https://myapp.demolocal.online → localhost:3000

# Expose multiple services
demolocal frontend 3000 &
demolocal backend 8080 &
demolocal database 5432 &
```

## CLI Reference

```
demolocal v1.0.0 — Expose local services to the internet

Usage:
  demolocal <subdomain> <port> [options]
  demolocal auth <token>                  Save auth token (server: demolocal.online)
  demolocal config                        Show current config

Options:
  --server <url>    Override server URL (default: demolocal.online via wss://)
  --token <token>   Auth token (overrides saved config)
  --version, -v     Show version
  --help, -h        Show help

Examples:
  demolocal auth gt_abc123...             # Save token, ready to tunnel
  demolocal myapp 3000                    # https://myapp.demolocal.online → localhost:3000
  demolocal api 8080                      # https://api.demolocal.online → localhost:8080
  demolocal myapp 3000 --server localhost:8080  # local dev (ws://)
```

### Config File

The client stores config at `~/.demolocal/config.json`:
```json
{
  "server_url": "demolocal.online",
  "auth_token": "gt_7d27b9b49fea763e1633..."
}
```

The server is **pre-configured in the binary for production** (`wss://demolocal.online` = port 443).

For **local development**, override with:
```bash
demolocal myapp 3000 --server localhost:8080  # ws://localhost:8080
```

## Dashboard

Access the web dashboard at: **https://demolocal.online:8080** (or `http://<server-ip>:8080` from your network)

**Features:**
- **Dashboard** — Overview, stats, active tunnels, request rate
- **Tunnels** — Create/manage tunnels, reserve subdomains, view status
- **Setup & Install** — Client install with your personal auth token
- **Settings** — Change password, regenerate auth token
- **Request Logs** — Per-tunnel HTTP logs with method, path, status code, response time

## Server Configuration

Edit `.env` before running:

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GOTUNNEL_DOMAIN` | `demolocal.online` | Base domain for tunnel subdomains |
| `GOTUNNEL_SECRET` | (required) | Secret key for session encryption |
| `GOTUNNEL_DB_TYPE` | `sqlite` | Database: `sqlite` or `mysql` |
| `GOTUNNEL_SQLITE_DB_PATH` | `./data/gotunnel.db` | SQLite DB file |
| `GOTUNNEL_ADMIN_PORT` | `8080` | Dashboard & API port |
| `GOTUNNEL_PROXY_PORT` | `80` | HTTP port (for ACME challenges) |
| `GOTUNNEL_ALLOW_REGISTRATION` | `true` | Allow public registration |
| `GOTUNNEL_AUTO_TLS` | `true` | Enable automatic HTTPS (ZeroSSL/Let's Encrypt) |
| `GOTUNNEL_AUTO_TLS_EMAIL` | | Email for ACME certificate registration |
| `GOTUNNEL_AUTO_TLS_DIR` | `./data/certs` | Directory to cache TLS certificates |
| `GOTUNNEL_ZEROSSL_API_KEY` | | ZeroSSL API key (optional; uses Let's Encrypt if empty) |
| `GOTUNNEL_EXTRA_PROXIES` | | Route specific subdomains to internal services |
| `GOOGLE_CLIENT_ID` | | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | | Google OAuth client secret |
| `GOOGLE_REDIRECT_URL` | | Google OAuth redirect URL |

### Example `.env`

```env
GOTUNNEL_DOMAIN=demolocal.online
GOTUNNEL_SECRET=your-super-secret-key-change-this
GOTUNNEL_DB_TYPE=sqlite
GOTUNNEL_SQLITE_DB_PATH=./data/gotunnel.db
GOTUNNEL_ADMIN_PORT=8080
GOTUNNEL_PROXY_PORT=80
GOTUNNEL_ALLOW_REGISTRATION=true
GOTUNNEL_AUTO_TLS=true
GOTUNNEL_AUTO_TLS_EMAIL=admin@demolocal.online
GOTUNNEL_AUTO_TLS_DIR=./data/certs
GOTUNNEL_ZEROSSL_API_KEY=your-zerossl-api-key
GOTUNNEL_EXTRA_PROXIES=ollama.demolocal.online=http://10.11.0.9:11434,grafana.demolocal.online=http://localhost:3000
```

### Extra Proxies

Route specific subdomains directly to internal services (no tunnel client needed):

```env
GOTUNNEL_EXTRA_PROXIES=ollama.demolocal.online=http://10.11.0.9:11434,grafana.demolocal.online=http://localhost:3000
```

Format: `subdomain=upstream,subdomain=upstream,...`

Example: Access Ollama API without a tunnel client:
```bash
curl https://ollama.demolocal.online/api/models
# → proxied to http://10.11.0.9:11434/api/models
```

## Docker Deployment

### Quick Start
```bash
docker compose up -d
docker compose logs -f        # View logs
docker compose down           # Stop
```

### Rebuilding
```bash
docker compose build --no-cache
docker compose up -d
```

The Docker image:
- Cross-compiles all 5 client binaries during `docker build`
- Exposes ports: **8080** (admin), **80** (ACME), **443** (tunnels & WSS)
- Persists data in `gotunnel_data` volume (SQLite DB + TLS certs)
- Pre-built binaries available at `/download/demolocal-*`

### Data Persistence
```yaml
gotunnel_data:
  - Contains SQLite database
  - Contains TLS certificates (if auto-TLS enabled)
  - Mounts to `/app/data` in container
```

## Building from Source

### Prerequisites
- Go 1.22+
- (Optional) `air` for live reload: `go install github.com/air-verse/air@latest`

### Build Commands

```bash
# Install dependencies
make deps

# Build server & client for current platform
make build

# Cross-compile client for all platforms
make release-client

# Build Linux server binaries
make release-server

# Development with hot reload
make run-server
```

### Manual Build
```bash
# Build just the client
CGO_ENABLED=0 go build -o demolocal ./cmd/client

# Build for a specific platform
GOOS=linux GOARCH=amd64 go build -o demolocal-linux ./cmd/client
GOOS=darwin GOARCH=arm64 go build -o demolocal-macos ./cmd/client
GOOS=windows GOARCH=amd64 go build -o demolocal.exe ./cmd/client

# Build server
go build -o gotunnel-server ./cmd/server
```

## Tech Stack

- **Go 1.22** — Language, server & client
- **gorilla/websocket** — Secure WSS tunnel protocol
- **modernc.org/sqlite** — Pure-Go SQLite (zero CGO)
- **golang.org/x/crypto/acme/autocert** — Automatic HTTPS (ACME)
- **ZeroSSL** — External Account Binding (EAB) for ACME
- **Google OAuth 2.0** — Sign-in integration
- **Tailwind CSS** — Dashboard UI (via CDN)
- **html/template + embed** — Templates & assets embedded in binary

## Performance & Security

- **Firewall-Friendly** — Uses port 443 (HTTPS), not SSH or other protocols
- **Zero Overhead** — Single Go binary, minimal memory/CPU footprint
- **Connection Pooling** — Reuses HTTP connections where possible
- **HTTPS Everywhere** — Auto-TLS with ZeroSSL/Let's Encrypt
- **Token Validation** — Every request validated server-side
- **Session Encryption** — Secure cookies (same-site, http-only)

## Troubleshooting

### Client can't connect
```bash
# Test connectivity
curl -k https://demolocal.online/health

# Or test direct IP
curl -k https://<server-ip>:443
```

### Tunnel shows online but requests timeout
Ensure your local service is running:
```bash
netstat -an | grep 3000
telnet localhost 3000
```

### TLS certificate errors
1. Verify DNS resolves to your server IP
2. Ensure port 80 is open for ACME challenges
3. Check `GOTUNNEL_AUTO_TLS_EMAIL` is correct
4. Review logs: `docker compose logs gotunnel | grep -i tls`

## Contributing

Contributions welcome! Please fork, create a feature branch, test locally, and submit a PR.

## License

MIT — See [LICENSE](LICENSE) for details.

## Support

- **Documentation** — https://demolocal.online
- **Issues** — https://github.com/adisaputra10/ngrok/issues
- **Dashboard** — https://demolocal.online:8080

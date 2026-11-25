# relay-htcp

A high-performance **TCP-over-HTTP/2** tunneling tool implemented in Go: tunnels arbitrary TCP connections through standard HTTPS/HTTP/2 multiplexed streams. To network firewalls, ISPs, or middleboxes, tunnel traffic looks identical to normal Web traffic. It provides Bearer Token authentication, route-based access control, connection pooling, heartbeat auto-recovery, and an embedded modern Web management UI.

[中文文档 (README.md)](README.md)

---

## Architecture Overview

```
┌─────────────┐   127.0.0.1:2222    ┌──────────────────┐   HTTPS / HTTP/2   ┌──────────────────┐   127.0.0.1:22   ┌─────────────┐
│ ssh client  │ ──────────────────▶ │ relay-htcp client │ ═════════════════▶ │ relay-htcp server │ ───────────────▶ │  ssh server │
└─────────────┘                     └──────────────────┘  Control + Data    └──────────────────┘                  └─────────────┘
```

- **Server**: Deployed on a publicly accessible node, listening on standard HTTP/HTTPS ports.
- **Client**: Deployed inside private NAT networks, mapping local ports to remote target services via tunnel servers.
- **Transparent**: Existing business software requires no modification—just point clients (SSH, MySQL, Redis, RDP, etc.) to the local listening port.

---

## Features

- **HTTP/2 Multiplexing**: A single underlying TCP/TLS connection multiplexes control frames and arbitrary data streams, eliminating repetitive TLS handshakes.
- **Connection Pooling**: Configurable multi-slot tunnel connection pools with round-robin stream allocation.
- **Multi-Server & Failover**: Clients can configure multiple servers. Each local listener can select specific servers with `round_robin` or `failover` strategies.
- **CDN / Cloudflare Support (xhttp)**: Optional `transport: xhttp` splits bidirectional streams into short upload POSTs and long download GETs, bypassing CDN limitations on streaming HTTP request bodies.
- **Outbound Proxy**: Supports upstream HTTP CONNECT and SOCKS5 proxies on both client and server sides.
- **STCP Pair-to-Pair Tunneling**: Supports `type: stcp` routes. The server pairs a provider (exposing a local service) with visitors without listening on extra public ports.
- **Heartbeat & Auto-Recovery**: Built-in PING/PONG keepalive mechanism. Exponential backoff automatically recovers tunnels if disconnected or after server restarts.
- **Camouflage & Decoy**: Realistic browser User-Agents, nginx-like response headers, and static decoy web pages for unknown paths.
- **Embedded Web Admin Panel**:
  - Zero external dependencies, pure vanilla JS + modern CSS, embedded into the binary using `go:embed`.
  - Live status cards, connection pools, and real-time streams.
  - Interactive pure SVG daily & 14-day history traffic charts.
  - Structured web form & YAML configuration editor with hot-reloading.
  - Token management with daily/weekly/monthly quota rate-limiting.
  - IP access control with CIDR whitelist/blacklist support.
  - Dark, light, and black themes.
- **Zero-Config Bootstrap**: Both client and server can launch without a configuration file (`-config`), automatically generating initial files and admin credentials.
- **Single Self-Contained Binary**: Built with `CGO_ENABLED=0` and modern embedded SQLite, requiring no external shared libraries or runtime dependencies.

---

## Quick Start

### 1. Requirements

- Go 1.22 or higher (if compiling from source)
- Linux, macOS, or Windows

### 2. Installation & Compilation

```bash
# Clone the repository
git clone https://github.com/your-username/relay-htcp.git
cd relay-htcp

# Build for current platform
make build
# Or directly with go:
go build -trimpath -o relay-htcp ./cmd/relay-htcp
```

### 3. Server Setup

Create `server.yaml`:

```yaml
listen: ":5630"

# Optional TLS: leave empty for plain h2c (internal/testing)
tls:
  cert: "server.crt"
  key: "server.key"

auth:
  tokens:
    - name: dev-laptop
      token: "your-strong-random-token-here"
      routes: [ssh, mysql]

routes:
  - name: ssh
    target: "127.0.0.1:22"
  - name: mysql
    target: "127.0.0.1:3306"

log:
  level: warn

admin:
  enabled: true
  shared: true       # Mount admin UI directly under /admin on the tunnel port
  path: "/admin"
```

Start the server:

```bash
./relay-htcp server -config server.yaml
# Or start in background:
nohup ./relay-htcp server -config server.yaml >> server.log 2>> server.err &
```

> **Note**: If run without `-config`, the server starts with built-in defaults and prints a one-time admin password to stdout.

### 4. Client Setup

Create `client.yaml`:

```yaml
auth:
  token: "your-strong-random-token-here"

tls:
  insecure_skip_verify: false  # true only for self-signed certificates

servers:
  - name: primary
    url: "https://your-server-ip:5630"
    transport: http            # 'http' for direct h2; 'xhttp' for Cloudflare/CDN

listeners:
  - local: "127.0.0.1:2222"
    target: "ssh"
    servers: [primary]
    strategy: failover
  - local: "127.0.0.1:33060"
    target: "mysql"
    servers: [primary]
    strategy: round_robin

tunnel:
  connections: 2
  heartbeat: 15s
  reconnect_min: 1s
  reconnect_max: 30s

log:
  level: warn

admin:
  enabled: true
  listen: "127.0.0.1:15630"
```

Start the client:

```bash
./relay-htcp client -config client.yaml
```

Now connect to your local port:

```bash
ssh -p 2222 user@127.0.0.1
mysql -h 127.0.0.1 -P 33060 -u root -p
```

---

## Binary Frame Protocol

Tunnel streams (control and data) use an efficient, lightweight binary frame:

```
+--------+---------------------+--------------------+
| type   | length (BE32)       | payload            |
| 1 byte | 4 bytes             | length bytes       |
+--------+---------------------+--------------------+
```

| Type | Value | Description |
|---|---|---|
| `DATA` | `0x0` | Raw TCP data chunk (max 16,383 bytes per frame) |
| `PING` | `0x1` | Tunnel heartbeat request (Client → Server) |
| `PONG` | `0x2` | Tunnel heartbeat response (echoes PING payload) |
| `CLOSE`| `0x3` | Graceful stream shutdown |
| `NOOP` | `0x4` | Padding frame (used for CDN buffer flushing) |
| `START`| `0x5` | STCP handshake: signals provider to dial local service |

---

## Configuration Reference

### Common Server Options (`server.yaml`)

```yaml
listen: ":5630"          # Tunnel listening address
routes:
  - name: ssh
    type: tcp            # tcp (default) or stcp
    target: "127.0.0.1:22"
  - name: internal-web
    type: stcp           # Pair provider with visitor streams
    bind: "127.0.0.1:8080" # Optional: expose provider locally on server
tunnel:
  max_concurrent_streams: 128
  dial_timeout: 10s
  idle_timeout: 90s
disguise:
  enabled: true
log:
  level: warn            # debug, info, warn, error
```

### Common Client Options (`client.yaml`)

```yaml
servers:
  - name: cloudflare-node
    url: "https://tunnel.example.com"
    transport: xhttp     # CDN/Cloudflare compatible mode
    xhttp_path: "/relay"
proxy:
  enabled: false
  type: socks5           # http or socks5
  address: "127.0.0.1:7890"
tunnel:
  connections: 2         # Number of parallel tunnels per server
  reconnect_min: 1s      # Initial reconnect retry interval
  reconnect_max: 30s     # Maximum exponential backoff ceiling
```

---

## Web Management Panel

Open the admin panel in your browser:
- **Server UI**: `http://<server-ip>:5630/admin/` (or configured admin port)
- **Client UI**: `http://127.0.0.1:15630/admin/`

### Features
- **Real-Time Monitoring**: Active stream inspection, uptime, incoming/outgoing throughput counters.
- **Traffic Analytics**: Interactive daily traffic and 14-day history bar charts.
- **Token Management**: Add, delete, enable/disable tokens and configure per-token bandwidth quotas.
- **Live Config Editor**: Edit server/client configuration via structured web forms or raw YAML with hot-reloading.
- **One-Click Restart**: Restart client tunnels and listeners directly from the web panel.

---

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

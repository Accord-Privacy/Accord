# Accord Relay Server — Admin Guide

This guide covers installation, configuration, deployment, and ongoing administration of an Accord relay server.

> **Key concept:** The Accord relay is a *zero-knowledge* routing layer. It never decrypts user content. As an admin, you manage infrastructure, not user data.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Configuration](#2-configuration)
3. [TLS Setup](#3-tls-setup)
4. [Database](#4-database)
5. [Deployment](#5-deployment)
6. [Node Management](#6-node-management)
7. [Moderation](#7-moderation)
8. [Monitoring](#8-monitoring)
9. [Backup & Recovery](#9-backup--recovery)
10. [Updating](#10-updating)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Installation

### Prerequisites

- **Rust 1.86+** — [rustup.rs](https://rustup.rs)
- **System dependencies** (Debian/Ubuntu):
  ```bash
  sudo apt install build-essential pkg-config libssl-dev
  ```

### From Source

```bash
git clone https://github.com/Accord-Privacy/Accord.git
cd Accord
cargo build --release -p accord-server
```

The binary is at `./target/release/accord-server`. Copy it somewhere on your PATH:

```bash
sudo cp target/release/accord-server /usr/local/bin/
```

### Docker

Build the image locally:

```bash
docker build -t accord-server .
```

Or run directly:

```bash
docker run -d \
  --name accord \
  -p 8080:8080 \
  -v accord-data:/data \
  accord-server \
  --host 0.0.0.0 --port 8080 --database /data/accord.db
```

### Quick Deploy Script

The included `deploy/install.sh` automates a Docker Compose deployment with Caddy for automatic TLS:

```bash
cd deploy
bash install.sh
```

It will prompt for your domain and admin token, write a `.env` file, and launch containers via `docker compose up -d`.

---

## 2. Configuration

Accord accepts configuration from three sources. **Priority order** (highest wins):

1. **CLI flags** — override everything
2. **TOML config file** — via `--config <path>`
3. **Built-in defaults**

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-a, --host` | `0.0.0.0` | Bind address |
| `-p, --port` | `8080` | Server port |
| `-d, --database` | `accord.db` | SQLite database path |
| `--database-encryption` | `true` | Enable SQLCipher encryption at rest |
| `--tls-cert` | — | Path to TLS certificate PEM |
| `--tls-key` | — | Path to TLS private key PEM |
| `-c, --config` | — | Path to TOML config file |
| `--cors-origins` | auto | Comma-separated allowed origins (`*` for any) |
| `--metadata-mode` | `standard` | `standard` or `minimal` (strips optional metadata) |
| `--frontend` | — | Path to frontend dist directory to serve |
| `--build-hash-enforcement` | `off` | `off`, `warn`, or `strict` |
| `--mesh-enabled` | `false` | Enable relay mesh for cross-relay DMs |
| `--mesh-port` | `9443` | Mesh listen port |
| `--mesh-peers` | — | Comma-separated bootstrap peers (`host:port`) |
| `--mesh-data-dir` | `mesh_data` | Mesh identity/state directory |

### TOML Config File

See [`deploy/config.example.toml`](../deploy/config.example.toml) for a full example:

```toml
host = "0.0.0.0"
port = 8080
database = "/var/lib/accord/accord.db"
database_encryption = true
metadata_mode = "standard"
cors_origins = "https://app.example.com"
build_hash_enforcement = "off"

# TLS (omit if behind a reverse proxy)
# tls_cert = "/etc/accord/tls/cert.pem"
# tls_key  = "/etc/accord/tls/key.pem"

# Relay Mesh
mesh_enabled = false
mesh_port = 9443
mesh_peers = ""
mesh_data_dir = "/var/lib/accord/mesh"
```

### Environment Variables

The Docker Compose setup uses environment variables via `.env`:

| Variable | Description |
|----------|-------------|
| `ACCORD_PORT` | Server port (default `8080`) |
| `ACCORD_DOMAIN` | Domain for Caddy TLS |
| `ACCORD_ADMIN_TOKEN` | Admin authentication token |

### CORS Behavior

- Binding to `0.0.0.0` or `::` → defaults to `*` (allow any origin)
- Binding to `localhost` → defaults to `http://localhost:3000,http://localhost:5173`
- Override with `--cors-origins` for production

---

## 3. TLS Setup

### Option A: Direct TLS (built-in)

Generate or obtain a certificate and key, then pass both:

```bash
accord-server --tls-cert /etc/accord/tls/cert.pem --tls-key /etc/accord/tls/key.pem
```

Both `--tls-cert` and `--tls-key` must be provided together. The server uses rustls (no OpenSSL dependency).

**Self-signed certificate (testing only):**

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=accord.local"
```

### Option B: Let's Encrypt via Caddy (recommended)

The included Docker Compose setup uses Caddy, which automatically obtains and renews Let's Encrypt certificates. Just set your domain:

```bash
# In .env
ACCORD_DOMAIN=chat.example.com
```

Caddy handles certificate issuance, renewal, and HTTPS termination. The Accord server runs plain HTTP behind it.

### Option C: Let's Encrypt via Certbot

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d chat.example.com

accord-server \
  --tls-cert /etc/letsencrypt/live/chat.example.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/chat.example.com/privkey.pem
```

Set up auto-renewal:

```bash
sudo certbot renew --dry-run
# Certbot installs a systemd timer automatically
```

---

## 4. Database

Accord uses **SQLite** as its data store, with optional SQLCipher encryption at rest.

### Database Location

| Setup | Default Path |
|-------|-------------|
| Binary | `./accord.db` (working directory) |
| systemd | `/var/lib/accord/accord.db` |
| Docker | `/data/accord.db` (volume-mounted) |

Override with `-d` / `--database`:

```bash
accord-server --database /var/lib/accord/accord.db
```

### SQLCipher Encryption

Enabled by default (`--database-encryption true`). On first run, Accord generates a random encryption key and stores it at `<database>.key` (e.g., `accord.db.key`).

- **Guard the `.key` file** — without it, the database is unreadable
- To disable: `--database-encryption false`
- Requires the `sqlcipher` feature at compile time

### WAL Mode

SQLite is configured in WAL (Write-Ahead Logging) mode for concurrent read performance. This creates additional files alongside the database:

- `accord.db-wal` — write-ahead log
- `accord.db-shm` — shared memory index

**Do not delete these files while the server is running.** They are checkpointed automatically.

### Backup & Restore Commands

```bash
# Create a backup (compressed archive)
accord-server backup -d /var/lib/accord/accord.db --output /backups/accord-backup.tar.gz

# Hot backup (safe while server is running)
accord-server backup -d /var/lib/accord/accord.db --hot

# Restore from backup
accord-server restore /backups/accord-backup.tar.gz -d /var/lib/accord/accord.db

# Skip confirmation prompt
accord-server restore /backups/accord-backup.tar.gz -d /var/lib/accord/accord.db -y
```

Both commands automatically handle SQLCipher encryption if a `.key` file exists alongside the database path.

---

## 5. Deployment

### systemd Service

Install the provided unit file:

```bash
# Create service user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/accord accord

# Create directories
sudo mkdir -p /var/lib/accord /etc/accord
sudo chown accord:accord /var/lib/accord

# Install binary and config
sudo cp target/release/accord-server /usr/local/bin/
sudo cp deploy/config.example.toml /etc/accord/config.toml
# Edit /etc/accord/config.toml to your needs

# Install service
sudo cp deploy/accord.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now accord
```

The unit file includes security hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`.

Manage the service:

```bash
sudo systemctl status accord
sudo systemctl restart accord
sudo journalctl -u accord -f          # follow logs
```

### Docker Compose

The project includes a production-ready `docker-compose.yml` with Caddy for automatic TLS:

```bash
# Create .env with your settings
cat > .env <<EOF
ACCORD_DOMAIN=chat.example.com
ACCORD_PORT=8080
ACCORD_ADMIN_TOKEN=$(openssl rand -hex 24)
EOF

# Start
docker compose up -d

# View logs
docker compose logs -f accord-server

# Stop
docker compose down
```

The Compose stack includes:
- **accord-server** — the relay, with health checks, data volume, mesh port exposed
- **caddy** — reverse proxy with automatic Let's Encrypt TLS

### Reverse Proxy (manual)

If you run your own reverse proxy instead of the bundled Caddy:

**Caddy:**

```
chat.example.com {
    reverse_proxy localhost:8080
}
```

**Nginx:**

```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;  # keep WebSockets alive
    }
}
```

> **Important:** WebSocket support (`Upgrade` / `Connection` headers) is required. Without it, clients cannot connect.

---

## 6. Node Management

A **Node** is a community space (like a Discord server). The relay server admin and Node admins are independent roles.

### Node Creation Policies

The server supports four creation policies:

| Policy | Description |
|--------|-------------|
| `open` | Anyone can create a Node (default) |
| `admin_only` | Only the server admin can create Nodes |
| `approval` | Node creation requires server admin approval |
| `invite` | Nodes can only be created via invite |

### Node Roles

Each Node has its own role hierarchy:

- **Admin** — full control over the Node (manages channels, roles, members)
- **Moderator** — can kick/ban, manage messages, create invites
- **Member** — baseline permissions from the `@everyone` role

The Node creator automatically becomes Admin.

### Permission System

Permissions are stored as a 64-bit bitmask (compatible with Discord's layout). Key permission bits:

| Bit | Permission | Description |
|-----|-----------|-------------|
| 0 | `CREATE_INVITE` | Create invite links |
| 1 | `KICK_MEMBERS` | Remove members |
| 2 | `BAN_MEMBERS` | Ban members |
| 3 | `ADMINISTRATOR` | Full access, bypasses all checks |
| 4 | `MANAGE_CHANNELS` | Create/edit/delete channels |
| 5 | `MANAGE_NODE` | Edit Node settings |
| 10 | `VIEW_CHANNEL` | See the channel |
| 11 | `SEND_MESSAGES` | Post messages |
| 13 | `MANAGE_MESSAGES` | Delete/pin others' messages |
| 28 | `MANAGE_ROLES` | Manage roles below own highest |

**Resolution order:** `@everyone` → role union (OR) → channel overwrites (allow/deny)

Roles have a position hierarchy — members can only modify roles below their highest role.

### Channel Permission Overwrites

Channels can override computed permissions for specific roles via allow/deny bitmasks:

```
PUT /channels/:id/permissions/:role_id  — set overwrite
DELETE /channels/:id/permissions/:role_id  — remove overwrite
GET /channels/:id/effective-permissions  — view computed result
```

---

## 7. Moderation

### Slow Mode

Set a per-channel cooldown between messages:

```
PUT /channels/:id/slow-mode  — set interval (seconds)
GET /channels/:id/slow-mode  — get current setting
```

### Word Filters (Auto-Mod)

Node admins can maintain a blocked word list:

```
GET  /nodes/:id/auto-mod/words      — list filtered words
POST /nodes/:id/auto-mod/words      — add a word
DELETE /nodes/:id/auto-mod/words/:word — remove a word
```

### Bans

```
POST   /nodes/:id/bans       — ban a user
DELETE /nodes/:id/bans       — unban a user
GET    /nodes/:id/bans       — list bans
GET    /nodes/:id/ban-check  — check if a user is banned
```

### Audit Logging

Every administrative action is logged in the Node's audit log:

```
GET /nodes/:id/audit-log  — view Node-level audit entries
```

Relay-level audit log (server admin):

```
GET /api/admin/audit-log          — all relay audit events
GET /api/admin/audit-log/actions  — list of audit action types
```

---

## 8. Monitoring

### Health Endpoint

```bash
curl http://localhost:8080/health
```

The Docker Compose health check polls this endpoint every 30 seconds.

### Admin Dashboard

Access the built-in admin dashboard at:

```
GET /admin        — HTML dashboard page
GET /admin/stats  — JSON server statistics
GET /admin/users  — JSON user list
GET /admin/nodes  — JSON node list
```

### Live Log Streaming

Connect to the admin WebSocket for real-time log output:

```
WS /admin/logs
```

### Logs

**systemd:**
```bash
sudo journalctl -u accord -f
sudo journalctl -u accord --since "1 hour ago"
```

**Docker:**
```bash
docker compose logs -f accord-server
docker compose logs --since 1h accord-server
```

The server uses `tracing` for structured logging. Log level is controlled via the `RUST_LOG` environment variable:

```bash
RUST_LOG=info accord-server          # default
RUST_LOG=debug accord-server         # verbose
RUST_LOG=accord_server=debug accord-server  # debug only for accord
```

---

## 9. Backup & Recovery

### Manual Backup

```bash
# Cold backup (server stopped)
accord-server backup -d /var/lib/accord/accord.db

# Hot backup (server running — uses VACUUM INTO)
accord-server backup -d /var/lib/accord/accord.db --hot

# Custom output path
accord-server backup -d /var/lib/accord/accord.db --output /backups/accord-$(date +%F).tar.gz
```

The backup command produces a `.tar.gz` archive containing the database and (if encrypted) handles SQLCipher transparently.

### Restore

```bash
# Stop the server first for cold restore
sudo systemctl stop accord

accord-server restore /backups/accord-2026-02-18.tar.gz -d /var/lib/accord/accord.db -y

sudo systemctl start accord
```

### Scheduled Backups

Add a cron job for automated hot backups:

```bash
# /etc/cron.d/accord-backup
0 3 * * * accord /usr/local/bin/accord-server backup -d /var/lib/accord/accord.db --hot --output /backups/accord-\$(date +\%F).tar.gz
```

**Docker:**
```bash
# Backup from running container
docker exec accord-server accord-server backup -d /data/accord.db --hot --output /data/backup.tar.gz
docker cp accord-server:/data/backup.tar.gz /backups/accord-$(date +%F).tar.gz
```

### What to Back Up

| Item | Path | Critical |
|------|------|----------|
| Database | `accord.db` | ✅ Yes |
| Encryption key | `accord.db.key` | ✅ Yes (if encryption enabled) |
| Config file | `/etc/accord/config.toml` | Recommended |
| TLS certificates | `/etc/accord/tls/` | Recommended |
| Mesh identity | `mesh_data/` | If mesh enabled |

---

## 10. Updating

### From Source

```bash
cd Accord
git pull
cargo build --release -p accord-server
sudo systemctl stop accord
sudo cp target/release/accord-server /usr/local/bin/
sudo systemctl start accord
```

### Docker

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Database Migrations

Accord runs database migrations automatically on startup. No manual migration step is required. The server will:

1. Detect the current schema version
2. Apply any pending migrations
3. Continue startup

**Always back up before upgrading:**

```bash
accord-server backup -d /var/lib/accord/accord.db --hot --output /backups/pre-upgrade-$(date +%F).tar.gz
```

---

## 11. Troubleshooting

### Server Won't Start

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Address already in use" | Port conflict | Change `--port` or stop conflicting service |
| "Failed to load TLS cert/key" | Bad cert path or format | Verify PEM files exist and are readable |
| "Both --tls-cert and --tls-key must be provided" | Only one TLS flag set | Provide both or neither |
| Database errors on startup | Corrupt DB or missing key | Restore from backup; check `.key` file |

### WebSocket Connection Issues

- **Behind Nginx:** Ensure `proxy_set_header Upgrade` and `Connection "upgrade"` are set
- **Timeout disconnects:** Set `proxy_read_timeout 86400s` (or higher) in your reverse proxy
- **Mixed content:** If serving HTTPS, clients must connect via `wss://`, not `ws://`
- **CORS errors:** Check `--cors-origins` includes your client's origin

### TLS Errors

- **Certificate chain incomplete:** Use `fullchain.pem`, not just `cert.pem`
- **Permission denied on key file:** Ensure the `accord` user can read the key
- **Let's Encrypt rate limits:** Use staging for testing: `certbot --staging`
- **Self-signed cert rejected:** Clients must trust the CA or use `--danger-accept-invalid-certs` (dev only)

### Performance

- **High memory:** Check connected WebSocket count via `/admin/stats`
- **Slow queries:** Enable `RUST_LOG=debug` temporarily to identify slow operations
- **WAL file growing:** The WAL is checkpointed automatically; if it grows very large, restart the server to force a checkpoint

### Docker-Specific

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' accord-server

# Shell into container
docker exec -it accord-server /bin/bash

# Reset everything (⚠️ destroys data)
docker compose down -v
```

### Getting Help

- **Logs first:** 90% of issues are visible in `journalctl -u accord` or `docker compose logs`
- **Health check:** `curl localhost:8080/health` — if this fails, the server isn't running
- **GitHub Issues:** [github.com/Accord-Privacy/Accord/issues](https://github.com/Accord-Privacy/Accord/issues)
- **Security issues:** Use [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories) — never public issues

# Accord Relay Server — Admin Guide

This guide covers installation, configuration, deployment, and ongoing administration of an Accord relay server.

> **Key concept:** The Accord relay is designed as a *zero-knowledge* routing layer. It never decrypts user content. As an admin, you manage infrastructure, not user data.
>
> **Current limitation:** attachments uploaded before end-to-end-encrypted attachments shipped (legacy uploads, kept read-only until they are retired) are encrypted under a key derived from the channel ID, so anyone with the database, the legacy file store or a backup can decrypt them; relay-mode voice keys pass through the relay. New attachments are end-to-end encrypted, but the relay still sees their metadata, and `accord-server backup` does not include `attachments_dir` (see [SELF-HOSTING.md](SELF-HOSTING.md#attachment-storage)). Protect backups accordingly; see [../SECURITY.md](../SECURITY.md#known-limitations).
>
> **You are the relay owner if you have localhost access to the machine.** There is no relay account and no login — the admin dashboard binds to `127.0.0.1` only. Your powers are a landlord's: see node **names and descriptions**, create/delete nodes, view a node-correlation-free **connection log** and ban an IP for abuse defense, and pin allowed client build hashes. You **cannot** see node membership, messages, channels, roles, a user roster, or any per-node governance — and the connection log is not shown to node owners. Note that P2P voice and P2P screen sharing reveal users' IP addresses to other call participants (see [../SECURITY.md](../SECURITY.md#known-limitations)). See **[../GOVERNANCE.md](../GOVERNANCE.md)**.

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
| `--no-tls` | `false` | Disable TLS (plain HTTP — dev, or behind a reverse proxy) |
| `--auto-tls` | — | Auto-generate a self-signed cert on startup (default when no cert given) |
| `--admin-port` | `6789` | Admin dashboard port, **bound to `127.0.0.1` only** |
| `--no-admin` | `false` | Disable the localhost admin dashboard entirely |
| `--disable-rate-limits` | `false` | **Dev/load-testing only** — requires `--no-tls`; never use in production. Also disables the membership, join-request and invite-preview limits |
| `--preview-rate-limit` | `30` | Unauthenticated invite previews (`GET /invites/:code/preview`) allowed per 60 s per client network (IPv4 address or IPv6 /64 of the socket peer). `0` disables the limit. See [Invite previews behind a reverse proxy](#invite-previews-behind-a-reverse-proxy) |
| `--legacy-invite-grace-hours` | `168` | Grace period for invites that were created before the admission upgrade without an expiry: at the first boot of the admission release they get `expires_at` = that boot + this many hours. `0` makes them expire at once. Applied once; see [Upgrading to relay admission](#upgrading-to-relay-admission) |
| `--keep-legacy-permanent-invites` | `false` | Keep those pre-upgrade invites permanent instead. The choice is recorded at the first boot and is final |
| `-c, --config` | — | Path to TOML config file |
| `--cors-origins` | auto | Comma-separated allowed origins (`*` for any) |
| `--metadata-mode` | `standard` | `standard` or `minimal` (strips optional metadata) |
| `--frontend` | — | Path to frontend dist directory to serve |
| `--build-hash-enforcement` | `off` | `off`, `warn`, or `strict` |
| `--mesh-enabled` | `false` | Enable relay mesh for cross-relay DMs |
| `--mesh-port` | `9443` | Mesh listen port |
| `--mesh-peers` | — | Comma-separated bootstrap peers (`host:port`) |
| `--mesh-data-dir` | `mesh_data` | Mesh identity/state directory |

The admission flags (`--preview-rate-limit`, `--legacy-invite-grace-hours`, `--keep-legacy-permanent-invites`) are command-line flags only; the TOML file does not set them.

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
| `ACCORD_ADMIN_TOKEN` | **Optional.** The admin dashboard is localhost-only, so this is unset by default (localhost access is the relay owner). Set it only if you deliberately expose the admin port through your own tunnel/proxy and want an extra `x-admin-token` gate. |

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

### Invite previews behind a reverse proxy

The unauthenticated invite preview (`GET /invites/:code/preview`) is limited per client network, keyed on the **socket peer address** the relay sees: the IPv4 address, or the /64 prefix of an IPv6 address. The relay never keys on `X-Forwarded-For` or `X-Real-IP`, because clients can forge them.

- **Proxy on the same host** (the Caddy and Nginx setups above): every request arrives from a loopback address. The relay does **not** apply the preview limit to loopback peers, because they would all share one bucket and one client could block previews for everyone. Limit `/invites/` at the proxy if you need a per-client limit there.
- **Proxy on another host:** every client shares the proxy's address, and therefore one bucket. Run the relay with `--preview-rate-limit 0` and limit at the proxy instead.
- **No proxy:** the limit applies per client network as described.

Invite codes are 22 random characters (about 131 bits), so the preview limit is defence in depth, not the main protection against guessing codes. Authenticated invite redemption is charged to the user's membership-action budget (10 per minute) before the code is looked up.

---

## 6. Node Management

A **Node** is a community space (like a Discord server). The **relay owner** (localhost access) and **node owners** are independent roles — the relay owner can create/delete nodes and see their names/descriptions, but has no authority or visibility inside a node.

### Node Creation Policies

The server supports four creation policies:

| Policy | Description | Status |
|--------|-------------|--------|
| `open` | Anyone can create a Node (default) | Implemented |
| `admin_only` | Only the relay owner can create Nodes | Implemented |
| `approval` | Node creation requires relay-owner approval | Planned — not yet enforced |
| `invite` | Nodes can only be created via invite | Planned — not yet enforced |

### Joining a Node (relay admission)

The relay admits a user to a node only with:

- a valid **invite**, validated and consumed atomically (use limits hold under concurrent redemptions, and an invite stops working when it expires, runs out, is revoked, or its creator loses the right to admit people);
- a **join request** approved by someone with admission authority, on a node whose owner switched `join_policy` to `request`; or
- the node's **owner** returning to their own node.

A node id alone grants nothing. Every admission path checks key bans, device bans and the per-device account cap, and the node's build allowlist (an absent `X-Build-Hash` counts as the empty string). On a node with at least one device ban, every admission needs a device fingerprint. The relay enforces all of this, so it necessarily knows which accounts are members of which node, and it sees pending join requests (who asked to join which node, for up to 14 days).

**Admission authority** means owning the node, or being a member whose roles grant CREATE_INVITE (ADMINISTRATOR implies it). It is needed to create, list and revoke invites and to approve or deny join requests. CREATE_INVITE therefore means "may admit people".

The DM system node (`00000000-0000-0000-0000-000000000001`, named `__dm_system__`) holds the DM channels. It is reserved: no one can join it, own it, invite into it or delete it, and every node route answers it as a node that does not exist. Database triggers keep these rules even for code paths that would try otherwise.

Admission protects members from other users of an honest relay. It does not protect them from the relay operator, who can change the code and the database.

### Node Roles

Each Node has its own role hierarchy:

- **Admin** — full control over the Node (manages channels, roles, members)
- **Moderator** — can kick/ban, manage messages, create invites (that is, admit people)
- **Member** — baseline permissions from the `@everyone` role

The Node creator automatically becomes Admin.

### Permission System

Permissions are stored as a 64-bit bitmask (compatible with Discord's layout). Key permission bits:

| Bit | Permission | Description |
|-----|-----------|-------------|
| 0 | `CREATE_INVITE` | Admit people: create, list and revoke invites, approve or deny join requests |
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

> **Moderation is the node owner's job, not the relay's.** The relay performs no
> content moderation and cannot — it is not meant to see plaintext (except files
> and relay-mode voice today; see [../SECURITY.md](../SECURITY.md#known-limitations)). Everything below is
> operated by node owners/moderators; the relay only routes or stores opaque
> values it can't interpret. See [../GOVERNANCE.md](../GOVERNANCE.md).

### Slow Mode

Set a per-channel cooldown between messages (relay enforces timing only, not content):

```
PUT /channels/:id/slow-mode  — set interval (seconds)
GET /channels/:id/slow-mode  — get current setting
```

### Word Filters (client-side)

Word filtering is **client-side** and lives entirely inside the node. The node
owner's blocklist is distributed to members inside the NMK-encrypted node
settings blob and enforced by each member's client before a message is sent.
**The relay never sees the list** — and because messages are E2E encrypted, it
could not match against it anyway. There are no relay auto-mod endpoints.

Note: like all client-cooperative controls, a member running a modified client
can bypass it. This matches Accord's model — moderation is a node-owner tool
within a trusted membership, not a guarantee enforced by the infrastructure.

### Bans

```
POST   /nodes/:id/bans       — ban a user
DELETE /nodes/:id/bans       — unban a user
GET    /nodes/:id/bans       — list bans
GET    /nodes/:id/ban-check  — check if a user is banned
```

Ban reasons are stored encrypted; the relay routes the ban but cannot read it.

### Audit Logging

Administrative actions are logged in the **node's own** audit log, readable only
by the node owner/moderators — never aggregated for the relay owner:

```
GET /nodes/:id/audit-log  — view node-level audit entries
```

There is no relay-wide audit-log endpoint. The relay owner has no visibility
into per-node governance (kicks, bans, role changes).

---

## 8. Monitoring

### Health Endpoint

```bash
curl http://localhost:8080/health
```

The Docker Compose health check polls this endpoint every 30 seconds. Besides the status fields, the response carries `features` (the capability tokens this relay implements, such as `admission/1`) and `admission_since` (when this relay began enforcing admission, the first boot of the admission release, in Unix seconds).

### Admin Dashboard (localhost only)

The dashboard is served on a **separate listener bound to `127.0.0.1`** (default
port `6789`, set with `--admin-port`, disable with `--no-admin`). It is **not**
reachable on the public port — `/admin*` returns 404 there. Localhost access is
the relay owner, so no login is required by default.

```
# On the relay host:
GET  http://127.0.0.1:6789/admin        — HTML dashboard page
GET  http://127.0.0.1:6789/admin/stats  — aggregate stats (counts, uptime, memory, connections)
GET  http://127.0.0.1:6789/admin/nodes  — node registry: id, name, description, created_at only
WS   ws://127.0.0.1:6789/admin/logs     — live server log stream
```

To view it from your workstation, tunnel over SSH rather than exposing the port:

```bash
ssh -L 6789:127.0.0.1:6789 user@relay-host
# then open http://127.0.0.1:6789/admin locally
```

**Deliberately absent:** there is no user roster and no `/admin/users` (it would
correlate users to nodes), and no cross-node audit view. The node registry shows
names and descriptions only — nothing about who is inside a node. If you set
`ACCORD_ADMIN_TOKEN`, every dashboard request must then carry a matching
`x-admin-token` header (useful only if you expose the port beyond localhost).

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

Admission events (joins, invites, leaves, kicks, join requests and the boot repair) use the tracing target `accord::admission`. They never contain invite codes, user ids or node ids at INFO or above. To see their DEBUG events: `RUST_LOG=info,accord::admission=debug`.

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

> **Backups contain decryptable legacy files.** Legacy uploads (from before end-to-end-encrypted attachments) are not end-to-end encrypted, so anyone who has a backup together with the legacy file store (`./data/files`) can decrypt them until they are retired. Blobs in `attachments_dir` cannot be decrypted without the keys in members' messages, but `accord-server backup` does not include them: back that directory up separately. Store backups as carefully as the live server.

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

### Upgrading to relay admission

The release that enforces relay admission changes data at its first boot. Read the operator release note in [CHANGELOG.md](../CHANGELOG.md#relay-admission-spec-01--operator-release-note) before upgrading. In short:

1. **Boot repair, at every start.** Before serving, the relay checks the DM system node and its system user and reverts any state an attacker could have created through the old login and join flaws. It runs in one transaction, changes nothing on a healthy database, and logs one WARN line per step that changed rows, with counts only:

   ```text
   WARN accord::admission: admission repair: step B5 changed 3 rows
   ```

   Such lines mean a past compromise was reverted. A step that may be skipped logs `admission repair: step B17 failed (<error class>); skipped` and the relay starts anyway.
2. **One-time migrations**, recorded in the `relay_migrations` table so they never run again:
   - `spec01_legacy_roles` — the legacy Admin and Moderator role conversion runs one last time, then the legacy role markers of everyone but node owners are reset to `member`;
   - `spec01_everyone_create_invite` — CREATE_INVITE is removed from every `@everyone` role;
   - `spec01_legacy_invite_expiry` — invites without an expiry get one (`--legacy-invite-grace-hours`, default 7 days), unless you pass `--keep-legacy-permanent-invites`. Its time is reported as `admission_since` in `GET /health`;
   - `spec01_audit_invite_codes` — invite codes are removed from existing audit entries.

   Each logs a WARN line with a count. Passing a flag at a later boot has no effect: the choice made at the first boot is final.
3. **Fail-closed start.** If a required repair step, the creation of the admission triggers or a one-time migration fails (for example because the database is read-only or locked), the relay exits with an error containing `admission repair failed` and does not serve. Fix the cause (permissions, disk space, another process holding the database) and start again. Clients see the relay as offline until then.

Restoring a backup taken before the upgrade runs the repair and the one-time migrations again at the next boot, with the invite grace period counted from that boot.

---

## 11. Troubleshooting

### Server Won't Start

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Address already in use" | Port conflict | Change `--port` or stop conflicting service |
| "Failed to load TLS cert/key" | Bad cert path or format | Verify PEM files exist and are readable |
| "Both --tls-cert and --tls-key must be provided" | Only one TLS flag set | Provide both or neither |
| Database errors on startup | Corrupt DB or missing key | Restore from backup; check `.key` file |
| "admission repair failed" | The boot repair, the admission triggers or a one-time migration could not run (read-only or locked database, full disk) | Fix the cause and restart; see [Upgrading to relay admission](#upgrading-to-relay-admission) |

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
- **Security issues:** Report privately at <https://github.com/Accord-Privacy/Accord/security/advisories/new> (**Report a vulnerability** on the repository's Security tab) — never public issues

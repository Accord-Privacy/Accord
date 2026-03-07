# Self-Hosting Quickstart

Host your own Accord relay server on a $5/mo VPS in under 30 minutes.

**What you need:** A domain name, a credit card for a VPS, and basic terminal skills.

---

## 1. Pick a VPS

Any of these work. Pick whichever has a datacenter near your users.

| Provider | Plan | Price | RAM | Disk | Regions | Notes |
|----------|------|-------|-----|------|---------|-------|
| [Hetzner](https://hetzner.cloud) | CX22 | €3.79/mo (~$4) | 2 GB | 20 GB | EU, US East | Best value. EU privacy laws. |
| [Vultr](https://vultr.com) | Regular Cloud | $6/mo | 1 GB | 25 GB | 32 locations | Most locations worldwide. |
| [DigitalOcean](https://digitalocean.com) | Basic Droplet | $6/mo | 1 GB | 25 GB | 15 locations | Best docs/UI for beginners. |
| [OVH](https://ovhcloud.com) | Starter VPS | €3.50/mo | 2 GB | 20 GB | EU, NA, APAC | Cheapest. Slower support. |

**Recommendation:** Hetzner CX22 if you're in EU/US East. DigitalOcean if you want the smoothest first-time experience.

**Specs:** Accord idles at ~20MB RAM. 1 vCPU / 512MB RAM handles hundreds of concurrent users easily.

**OS:** Choose **Ubuntu 24.04 LTS** when creating your server.

---

## 2. Initial Server Setup

SSH into your new server:

```bash
ssh root@YOUR_SERVER_IP
```

### Create a non-root user

```bash
adduser accord-admin
usermod -aG sudo accord-admin
```

### Enable firewall

```bash
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### Install fail2ban

```bash
apt update && apt install -y fail2ban
systemctl enable --now fail2ban
```

### Enable automatic security updates

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

Now log out and SSH back in as `accord-admin` for everything else.

---

## 3. DNS Setup

Before deploying, point your domain to your server.

1. Go to your DNS provider (Cloudflare, Namecheap, etc.)
2. Add an **A record**:
   - **Name:** `chat` (or whatever subdomain — e.g., `chat.yourdomain.com`)
   - **Value:** Your server's IP address
   - **TTL:** Auto / 300
3. If using Cloudflare, set proxy to **DNS only** (gray cloud) — Caddy needs direct access for Let's Encrypt

Verify it's working:

```bash
dig +short chat.yourdomain.com
# Should return your server IP
```

---

## 4A. Docker Compose Deployment (Recommended)

This is the easiest path. Caddy handles TLS automatically.

### Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

### Deploy

```bash
git clone https://github.com/Accord-Privacy/Accord.git
cd Accord
bash deploy/install.sh
```

The script will ask for your domain and admin token, then launch everything.

**That's it.** Caddy automatically gets a Let's Encrypt certificate. Your server is live at `https://chat.yourdomain.com`.

### Verify

```bash
curl https://chat.yourdomain.com/health
# Should return OK
```

### Useful commands

```bash
docker compose logs -f              # follow all logs
docker compose logs -f accord-server # just the server
docker compose restart              # restart everything
docker compose down                 # stop everything
docker compose up -d                # start everything
```

---

## 4B. Binary Deployment with systemd

For those who prefer no Docker overhead.

### Install build dependencies

```bash
sudo apt install -y build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Build

```bash
git clone https://github.com/Accord-Privacy/Accord.git
cd Accord
cargo build --release -p accord-server
sudo cp target/release/accord-server /usr/local/bin/
```

### Configure

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/accord accord
sudo mkdir -p /var/lib/accord /etc/accord
sudo chown accord:accord /var/lib/accord
sudo cp deploy/config.example.toml /etc/accord/config.toml
```

Edit `/etc/accord/config.toml`:

```toml
host = "0.0.0.0"
port = 8080
database = "/var/lib/accord/accord.db"
database_encryption = true
```

### Install systemd service

```bash
sudo cp deploy/accord.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now accord
```

### Add Caddy as reverse proxy (for TLS)

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Edit `/etc/caddy/Caddyfile`:

```
chat.yourdomain.com {
    reverse_proxy localhost:8080
    encode gzip zstd
}
```

```bash
sudo systemctl reload caddy
```

Caddy automatically obtains and renews Let's Encrypt certificates.

### Verify

```bash
sudo systemctl status accord
curl https://chat.yourdomain.com/health
```

---

## 5. TLS Notes

Both deployment options above use **Caddy for automatic TLS**. This is the recommended approach — zero config, auto-renewal, no cron jobs.

If you prefer certbot instead:

```bash
sudo apt install -y certbot
sudo certbot certonly --standalone -d chat.yourdomain.com
```

Then point Accord directly at the certs (no reverse proxy needed):

```toml
# In /etc/accord/config.toml
tls_cert = "/etc/letsencrypt/live/chat.yourdomain.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/chat.yourdomain.com/privkey.pem"
port = 443
```

Certbot auto-renews via systemd timer. You'll need to reload Accord after renewal — add a deploy hook:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/accord.sh << 'EOF'
#!/bin/bash
systemctl restart accord
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/accord.sh
```

---

## 6. Backups

### Automated daily backups

**Docker:**

```bash
# Add to crontab (crontab -e)
0 3 * * * docker exec accord-server accord-server backup -d /data/accord.db --hot --output /data/backup.tar.gz && docker cp accord-server:/data/backup.tar.gz /home/accord-admin/backups/accord-$(date +\%F).tar.gz
```

**systemd:**

```bash
# Add to crontab (crontab -e)
0 3 * * * /usr/local/bin/accord-server backup -d /var/lib/accord/accord.db --hot --output /home/accord-admin/backups/accord-$(date +\%F).tar.gz
```

### Keep 7 days of backups

```bash
# Add after the backup line
0 4 * * * find /home/accord-admin/backups -name "accord-*.tar.gz" -mtime +7 -delete
```

### Off-site backups

Sync to a second location. Pick one:

```bash
# rsync to another server
0 5 * * * rsync -az /home/accord-admin/backups/ backup-user@other-server:/backups/accord/

# Or use rclone to S3/B2/etc (cheap object storage)
# Setup: rclone config (one time)
0 5 * * * rclone sync /home/accord-admin/backups/ b2:my-accord-backups
```

### What to back up

- `accord.db` + `accord.db.key` — **critical** (the key is required to read encrypted databases)
- `/etc/accord/config.toml` — nice to have
- For Docker: the `accord-data` volume contains both DB and key

### Restore

```bash
sudo systemctl stop accord
accord-server restore /home/accord-admin/backups/accord-2026-03-07.tar.gz -d /var/lib/accord/accord.db -y
sudo systemctl start accord
```

---

## 7. Monitoring

### Health check

```bash
curl -sf http://localhost:8080/health || echo "DOWN"
```

### Simple uptime monitoring

Use a free service to ping your health endpoint:

- [UptimeRobot](https://uptimerobot.com) (free, 5-min checks)
- [Uptime Kuma](https://github.com/louislam/uptime-kuma) (self-hosted)
- [Healthchecks.io](https://healthchecks.io) (free, monitors cron jobs too)

### Logs

```bash
# Docker
docker compose logs -f accord-server

# systemd
sudo journalctl -u accord -f
sudo journalctl -u accord --since "1 hour ago"
```

### Admin dashboard

Accord has a built-in admin dashboard at `https://chat.yourdomain.com/admin` with stats, user list, and live log streaming.

### Disk space

Accord's database is small, but check periodically:

```bash
du -sh /var/lib/accord/    # systemd
docker system df            # Docker
```

---

## 8. Updating

### Docker

```bash
cd Accord
git pull
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Binary

```bash
cd Accord
git pull
cargo build --release -p accord-server
sudo systemctl stop accord
sudo cp target/release/accord-server /usr/local/bin/
sudo systemctl start accord
```

**Always back up before updating:**

```bash
accord-server backup -d /var/lib/accord/accord.db --hot --output /home/accord-admin/backups/pre-upgrade-$(date +%F).tar.gz
```

Database migrations run automatically on startup. No manual steps needed.

---

## 9. Generating Invite Links

Once your server is running, generate invite links for your users:

```bash
# Encode your host
echo -n "chat.yourdomain.com:443" | base64 | tr '+/' '-_' | tr -d '='
# Example output: Y2hhdC55b3VyZG9tYWluLmNvbTo0NDM

# Full invite link format:
# accord://BASE64_HOST/INVITE_CODE
```

Share the `accord://` link with your users. They'll paste it into the Accord desktop app to join.

---

## Quick Reference

| Task | Docker | systemd |
|------|--------|---------|
| Start | `docker compose up -d` | `sudo systemctl start accord` |
| Stop | `docker compose down` | `sudo systemctl stop accord` |
| Logs | `docker compose logs -f` | `sudo journalctl -u accord -f` |
| Restart | `docker compose restart` | `sudo systemctl restart accord` |
| Health | `curl localhost:8080/health` | `curl localhost:8080/health` |
| Backup | See §6 | See §6 |
| Update | See §8 | See §8 |

---

*For full configuration reference, see the [Admin Guide](admin-guide.md).*

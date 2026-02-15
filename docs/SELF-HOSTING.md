# Self-Hosting Guide for Accord Relay Server

This guide will help you deploy the Accord relay server on your own infrastructure using Docker. A sysadmin should be able to get this running in under 10 minutes.

## Prerequisites

- **Docker** (version 20.10 or later)
- **Docker Compose** (version 1.28 or later, or Docker Compose V2)
- Linux server with at least 512MB RAM and 2GB storage
- Domain name (optional but recommended for SSL)

### Install Docker & Docker Compose

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo apt-get install docker-compose-plugin
```

**CentOS/RHEL/Fedora:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo yum install docker-compose-plugin
```

## Quick Start (3 Commands)

1. **Clone and navigate to the project:**
```bash
git clone https://github.com/your-org/accord.git && cd accord
```

2. **Start the server:**
```bash
docker compose up -d --build
```

3. **Verify it's running:**
```bash
curl http://localhost:8080/health || docker compose logs accord-server
```

That's it! The Accord relay server is now running on `http://localhost:8080`.

## Configuration

### Environment Variables

Copy the example environment file and customize:

```bash
cp docker/.env.example .env
```

Edit `.env` with your preferred settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `ACCORD_HOST` | `0.0.0.0` | IP address to bind to (use `0.0.0.0` for all interfaces) |
| `ACCORD_PORT` | `8080` | Port the server listens on |
| `ACCORD_DB_PATH` | `/data/accord.db` | SQLite database file location |
| `ACCORD_NODE_CREATION_POLICY` | `open` | Who can create nodes: `open`, `invite-only`, or `closed` |
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, or `trace` |

### Node Creation Policies

- **`open`**: Anyone can create nodes (good for public instances)
- **`invite-only`**: Only invited users can create nodes
- **`closed`**: No new nodes can be created (admin-only)

### Custom Port Configuration

To run on a different port, update both the environment and docker-compose:

```yaml
# docker-compose.yml
ports:
  - "3000:3000"  # host:container
environment:
  - ACCORD_PORT=3000
```

## Reverse Proxy Setup

### Nginx with SSL

Create `/etc/nginx/sites-available/accord`:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL configuration (use Certbot for Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # WebSocket support
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

Enable and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/accord /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Caddy with Automatic SSL

Create a `Caddyfile`:

```
your-domain.com {
    reverse_proxy localhost:8080
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options DENY
        X-Content-Type-Options nosniff
    }
}
```

## Firewall Configuration

### UFW (Ubuntu)
```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS (if using reverse proxy)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow direct access (if not using reverse proxy)
sudo ufw allow 8080/tcp

sudo ufw enable
```

### firewalld (CentOS/RHEL)
```bash
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
# Or for direct access: --add-port=8080/tcp
sudo firewall-cmd --reload
```

## Backup Strategy

### SQLite Database Backup

The database is stored in the Docker volume. Create automated backups:

```bash
#!/bin/bash
# backup-accord.sh
BACKUP_DIR="/home/backups/accord"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Create consistent backup while server is running
docker exec accord-server sqlite3 /data/accord.db ".backup /tmp/backup.db"
docker cp accord-server:/tmp/backup.db "$BACKUP_DIR/accord_$DATE.db"
docker exec accord-server rm /tmp/backup.db

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "accord_*.db" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/accord_$DATE.db"
```

Schedule daily backups:
```bash
# Add to crontab
0 2 * * * /path/to/backup-accord.sh
```

### Volume Backup (Alternative)

```bash
# Stop container
docker compose down

# Backup entire volume
docker run --rm -v accord_accord_data:/data -v $(pwd):/backup ubuntu tar czf /backup/accord-data-backup.tar.gz -C /data .

# Restore from backup
docker run --rm -v accord_accord_data:/data -v $(pwd):/backup ubuntu tar xzf /backup/accord-data-backup.tar.gz -C /data

# Start container
docker compose up -d
```

## Updating to New Versions

### Standard Update Process

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose down
docker compose up -d --build

# Verify update
docker compose logs accord-server
```

### Zero-Downtime Update (Advanced)

```bash
# Scale up with new version
docker compose up -d --scale accord-server=2 --no-recreate

# Wait for health check
sleep 30

# Scale down old container
docker compose up -d --scale accord-server=1 --no-recreate

# Clean up old images
docker image prune -f
```

## Monitoring & Health Checks

### Built-in Health Check

The container includes a health check that runs every 30 seconds:

```bash
# Check container health
docker compose ps
docker inspect accord-server | grep -A5 '"Health"'
```

### External Health Monitoring

```bash
# Simple health check script
#!/bin/bash
if curl -f -s http://localhost:8080/health > /dev/null; then
    echo "$(date): Accord server is healthy"
else
    echo "$(date): Accord server is down - attempting restart"
    cd /path/to/accord && docker compose restart accord-server
fi
```

### Log Management

```bash
# View recent logs
docker compose logs -f accord-server

# View logs from last hour
docker compose logs --since 1h accord-server

# Rotate logs (prevent disk usage issues)
echo '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

## Security Best Practices

### Running as Non-Root

The Docker container already runs as a non-root `accord` user (UID 1000). No additional configuration needed.

### File Permissions

Ensure proper ownership of data directory:

```bash
# If mounting host directory instead of Docker volume
sudo chown -R 1000:1000 /path/to/data
sudo chmod 755 /path/to/data
```

### Network Isolation

Create a dedicated Docker network:

```yaml
# docker-compose.yml
version: '3.8'

services:
  accord-server:
    # ... existing config ...
    networks:
      - accord-internal

networks:
  accord-internal:
    driver: bridge
    internal: false  # Set to true for full isolation
```

### Environment File Security

```bash
# Secure the .env file
chmod 600 .env
chown root:root .env
```

### Additional Hardening

1. **Disable SSH password auth** (use keys only)
2. **Enable automatic security updates**
3. **Use fail2ban** for intrusion prevention
4. **Regular security audits** with tools like Lynis
5. **Monitor logs** for suspicious activity

## Troubleshooting

### Container Won't Start

```bash
# Check logs for errors
docker compose logs accord-server

# Common issues:
# 1. Port already in use
sudo netstat -tulpn | grep :8080

# 2. Permission issues with data directory
ls -la ./data/  # or check volume mount

# 3. Invalid environment variables
docker compose config  # validates compose file
```

### Database Corruption

```bash
# Check database integrity
docker exec accord-server sqlite3 /data/accord.db "PRAGMA integrity_check;"

# If corrupted, restore from backup
docker compose down
# ... restore backup ...
docker compose up -d
```

### High Memory Usage

```bash
# Monitor container resources
docker stats accord-server

# Set memory limits in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 512M
    reservations:
      memory: 256M
```

### Connection Issues

```bash
# Test internal connectivity
docker exec accord-server curl http://localhost:8080/health

# Test external connectivity (from host)
curl http://localhost:8080/health

# Check firewall rules
sudo ufw status verbose
# or
sudo firewall-cmd --list-all
```

### SSL Certificate Issues

```bash
# Verify certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Renew Let's Encrypt certificates
sudo certbot renew --dry-run
```

### Performance Issues

```bash
# Check system resources
htop
df -h
iostat -x 1

# Optimize SQLite database
docker exec accord-server sqlite3 /data/accord.db "VACUUM; ANALYZE;"

# Review log levels (reduce to 'warn' or 'error' for production)
# Edit .env and set RUST_LOG=warn
```

## Getting Help

- **Logs**: Always check `docker compose logs accord-server` first
- **Configuration**: Verify with `docker compose config`
- **Health**: Monitor with `docker compose ps` and `docker stats`
- **Community**: [GitHub Issues](https://github.com/your-org/accord/issues) for bug reports and feature requests

---

## Quick Reference

```bash
# Start server
docker compose up -d

# View logs
docker compose logs -f accord-server

# Restart server
docker compose restart accord-server

# Update server
git pull && docker compose up -d --build

# Backup database
docker exec accord-server sqlite3 /data/accord.db ".backup /tmp/backup.db"
docker cp accord-server:/tmp/backup.db ./backup.db

# Check health
curl http://localhost:8080/health
```

That's it! Your Accord relay server should now be running securely and reliably.
#!/bin/bash
# Accord Relay Server - Quick Stats CLI
# Usage: bash scripts/accord-stats.sh

DB="/home/clawbitch/.openclaw/workspace/Accord/accord.db"
PORT=8443

echo "═══════════════════════════════════════"
echo "  Accord Relay Server Stats"
echo "═══════════════════════════════════════"
echo ""

# Server health
HEALTH=$(curl -s http://localhost:$PORT/health 2>/dev/null)
if [ $? -eq 0 ]; then
    UPTIME=$(echo "$HEALTH" | grep -oP '"uptime_seconds":\K[0-9]+')
    echo "  Status:      🟢 Online"
    printf "  Uptime:      %dd %dh %dm %ds\n" $((UPTIME/86400)) $((UPTIME%86400/3600)) $((UPTIME%3600/60)) $((UPTIME%60))
else
    echo "  Status:      🔴 Offline"
fi

echo ""
echo "── Database ──"
echo "  Users:       $(sqlite3 $DB 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo 'N/A')"
echo "  Nodes:       $(sqlite3 $DB 'SELECT COUNT(*) FROM nodes;' 2>/dev/null || echo 'N/A')"
echo "  Tokens:      $(sqlite3 $DB 'SELECT COUNT(*) FROM auth_tokens;' 2>/dev/null || echo 'N/A')"
echo "  Messages:    $(sqlite3 $DB 'SELECT COUNT(*) FROM messages;' 2>/dev/null || echo 'N/A')"

echo ""
echo "── Nodes ──"
sqlite3 -column -header $DB "SELECT n.name, COUNT(nm.user_id) as members FROM nodes n LEFT JOIN node_members nm ON n.id = nm.node_id GROUP BY n.id;" 2>/dev/null || echo "  No nodes"

echo ""
echo "── Active Tokens ──"
sqlite3 $DB "SELECT u.public_key_hash, datetime(at.expires_at, 'unixepoch', 'localtime') as expires FROM auth_tokens at JOIN users u ON at.user_id = u.id;" 2>/dev/null || echo "  None"

echo ""
echo "── Disk ──"
echo "  DB size:     $(du -sh $DB 2>/dev/null | awk '{print $1}')"
echo "  Disk free:   $(df -h / | tail -1 | awk '{print $4}')"
echo ""

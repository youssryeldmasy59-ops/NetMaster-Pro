#!/usr/bin/env bash
# NetMaster Pro - Advanced Local Network Controller & Router Bandwidth Manager
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=================================================="
echo "⚡ NetMaster Pro - تشغيل لوحة التحكم في الشبكة والراوتر"
echo "=================================================="

# Start background ARP updater daemon
(
  while true; do
    /usr/sbin/arp -a > /tmp/netmaster_arp.txt 2>/dev/null
    sleep 3
  done
) &
ARP_PID=$!

# Start Cloudflare Tunnel for public HTTPS access
(
  cloudflared tunnel --url http://localhost:8080 2>&1 | tee /tmp/cloudflared.log
) &
CF_PID=$!

trap "kill $ARP_PID $CF_PID 2>/dev/null; exit" SIGINT SIGTERM EXIT

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "[*] جاري تجهيز بيئة التشغيل السريعة uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env
fi

sleep 2
PUBLIC_URL=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' /tmp/cloudflared.log 2>/dev/null | head -n 1)

echo "=================================================="
echo "🌐 رابط الموقع الأونلاين العام:"
echo "👉 $PUBLIC_URL"
echo "🏠 الرابط المحلي: http://localhost:8080"
echo "=================================================="

# Open browser
(sleep 1.5 && open "${PUBLIC_URL:-http://localhost:8080}") &

# Run server with uv
uv run --with fastapi --with uvicorn --with scapy python3 app.py

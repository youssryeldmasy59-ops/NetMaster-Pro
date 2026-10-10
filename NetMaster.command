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

trap "kill $ARP_PID 2>/dev/null; exit" SIGINT SIGTERM EXIT

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "[*] جاري تجهيز بيئة التشغيل السريعة uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env
fi

echo "[*] الخادم يعمل الآن على الرابط: http://localhost:8080"
echo "[*] للتحكم الكامل وقطع النت عن الأجهزة: يفضل تشغيل الأمر بـ sudo ./run.sh"
echo "=================================================="

# Open browser after 1.5 seconds
(sleep 1.5 && open "http://localhost:8080") &

# Run server with uv
uv run --with fastapi --with uvicorn --with scapy python3 app.py

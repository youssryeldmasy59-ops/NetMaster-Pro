#!/usr/bin/env bash
# NetMaster Pro v3.0 - Real Network Controller
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=================================================="
echo "⚡ NetMaster Pro v3.0 - Real Bandwidth Controller"
echo "=================================================="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  تنبيه: لازم تشغل بـ sudo عشان التحكم في السرعة يشتغل فعلياً!"
    echo "   شغّل: sudo ./run.sh"
    echo "   أو دوس مرتين على Run-NetMaster-Admin.command"
    echo ""
fi

# Copy index.html to static/ if not there
mkdir -p "$DIR/static"
if [ ! -f "$DIR/static/index.html" ] || [ "$DIR/index.html" -nt "$DIR/static/index.html" ]; then
    cp "$DIR/index.html" "$DIR/static/index.html" 2>/dev/null
fi

# Start background ARP updater daemon
(
  while true; do
    /usr/sbin/arp -a > /tmp/netmaster_arp.txt 2>/dev/null
    sleep 3
  done
) &
ARP_PID=$!

# Start Cloudflare Tunnel for public HTTPS access
rm -f /tmp/cloudflared.log
if command -v cloudflared &> /dev/null; then
    (
      cloudflared tunnel --url http://localhost:8080 2>&1 | tee /tmp/cloudflared.log
    ) &
    CF_PID=$!
else
    echo "[!] cloudflared مش مثبت — هتشتغل local فقط"
    echo "    ثبته بـ: brew install cloudflared"
    CF_PID=""
fi

trap "kill $ARP_PID $CF_PID 2>/dev/null; exit" SIGINT SIGTERM EXIT

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "[*] جاري تجهيز بيئة التشغيل السريعة uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env 2>/dev/null
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
fi

# Wait for tunnel
sleep 3
PUBLIC_URL=""
if [ -f /tmp/cloudflared.log ]; then
    PUBLIC_URL=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' /tmp/cloudflared.log 2>/dev/null | head -n 1)
fi

echo "=================================================="
if [ -n "$PUBLIC_URL" ]; then
    echo "🌐 رابط الموقع الأونلاين العام:"
    echo "👉 $PUBLIC_URL"
fi
echo "🏠 الرابط المحلي: http://localhost:8080"
echo "=================================================="

# Open browser
(sleep 1.5 && open "${PUBLIC_URL:-http://localhost:8080}") &

# Run server with uv
uv run --with fastapi --with uvicorn --with scapy python3 "$DIR/app.py"

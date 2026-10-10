#!/usr/bin/env bash
# NetMaster Pro v3.0 - Admin Privilege Launcher (Double-click to run)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=================================================="
echo "⚡ تشغيل NetMaster Pro بصلاحيات Root الكاملة"
echo "=================================================="
echo "[*] سيتم طلب باسورد الماك عشان نقدر نتحكم في الشبكة..."

# Use osascript to get admin privs and run
osascript <<EOF
do shell script "cd \"$DIR\" && ./run.sh" with administrator privileges
EOF

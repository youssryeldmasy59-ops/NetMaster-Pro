#!/usr/bin/env bash
# NetMaster Pro - Admin Privilege Launcher
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=================================================="
echo "⚡ تشغيل NetMaster Pro بصلاحيات الأدمن الكاملة (Root)"
echo "=================================================="
echo "[*] سيتم طلب باسورد الماك أو بصمة Touch ID لفتح صلاحيات كارت الشبكة..."

osascript <<EOF
do shell script "cd \"$DIR\" && ./run.sh" with administrator privileges
EOF

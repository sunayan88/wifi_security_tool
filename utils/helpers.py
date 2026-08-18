# ─────────────────────────────────────────
#  WiFi Security Tool — Helper Utilities
# ─────────────────────────────────────────

import subprocess
import re
import socket
from datetime import datetime


def get_current_wifi_name():
    try:
        result = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="utf-8", errors="ignore"
        )
        match = re.search(r"^\s+SSID\s*:\s(.+)", result, re.MULTILINE)
        return match.group(1).strip() if match else None
    except:
        return None


def get_wifi_security_type():
    try:
        result = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="utf-8", errors="ignore"
        )
        match = re.search(r"Authentication\s*:\s(.+)", result)
        return match.group(1).strip() if match else "UNKNOWN"
    except:
        return "UNKNOWN"


def get_local_ip():
    try:
        # Most reliable method — connects to external IP without sending data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            result = subprocess.check_output(
                ["ipconfig"], encoding="utf-8", errors="ignore"
            )
            match = re.search(r"IPv4 Address[.\s]+:\s([\d.]+)", result)
            return match.group(1).strip() if match else None
        except:
            return None


def get_subnet():
    ip = get_local_ip()
    if ip:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_mac(mac):
    return mac.upper() if mac else "UNKNOWN"
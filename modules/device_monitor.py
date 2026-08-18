# ─────────────────────────────────────────
#  WiFi Security Tool — Device Monitor
# ─────────────────────────────────────────

import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from utils.helpers import get_subnet, format_mac, get_current_wifi_name
from database.db_manager import save_device, get_known_device_macs, get_device_network_map
from modules.alert_system import generate_device_alert


# ─── ARP Scan via Scapy ───────────────────

def arp_scan(subnet=None):
    if not subnet:
        subnet = get_subnet()
    if not subnet:
        return []

    try:
        from scapy.all import ARP, Ether, srp
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        result = srp(packet, timeout=3, verbose=False)[0]
        devices = [{"ip": r.psrc, "mac": format_mac(r.hwsrc)} for _, r in result]
        if devices:
            return devices
    except Exception as e:
        pass

    # Fallback: wake up local hosts with ping, then read Windows ARP cache.
    populate_arp_cache(subnet)
    return arp_table_fallback()


def populate_arp_cache(subnet):
    """Ping local hosts briefly so Windows fills the ARP table."""
    try:
        hosts = [str(ip) for ip in ip_network(subnet, strict=False).hosts()]
    except:
        return

    def ping(ip):
        try:
            subprocess.run(
                ["ping", "-n", "1", "-w", "250", ip],
                capture_output=True,
                creationflags=0x08000000,
            )
        except:
            pass

    with ThreadPoolExecutor(max_workers=48) as pool:
        futures = [pool.submit(ping, ip) for ip in hosts]
        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass


# ─── ARP Table Fallback (no Scapy needed) ─

def arp_table_fallback():
    """Reads Windows ARP cache as a fallback."""
    try:
        result = subprocess.check_output(
            ["arp", "-a"],
            encoding="utf-8", errors="ignore"
        )
        devices = []
        for line in result.splitlines():
            match = re.match(
                r"\s+([\d.]+)\s+([\w-]+)\s+\w+", line
            )
            if match:
                ip  = match.group(1)
                mac = match.group(2).upper().replace("-", ":")
                if (
                    not ip.endswith(".255")
                    and not ip.startswith("224.")
                    and mac != "FF:FF:FF:FF:FF:FF"
                    and mac != "00:00:00:00:00:00"
                ):
                    devices.append({"ip": ip, "mac": mac})
        unique = {}
        for device in devices:
            unique[(device["ip"], device["mac"])] = device
        return list(unique.values())
    except:
        return []


# ─── Hostname Lookup ──────────────────────

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


# ─── Device Type Guess ────────────────────

def guess_device_type(hostname, mac):
    h = hostname.lower()
    if any(k in h for k in ["phone", "android", "iphone", "samsung", "redmi", "oneplus", "xiaomi"]):
        return "Mobile Device"
    if any(k in h for k in ["laptop", "pc", "desktop", "windows", "legion", "lenovo", "dell", "hp"]):
        return "Computer"
    if any(k in h for k in ["router", "gateway", "tplink", "dlink", "mikrotik", "asus"]):
        return "Router / Gateway"
    if any(k in h for k in ["tv", "smart", "roku", "firetv", "chromecast"]):
        return "Smart TV"
    if any(k in h for k in ["printer", "canon", "epson", "brother"]):
        return "Printer"
    return "Unknown Device"


def normalize_mac(mac):
    return (mac or "").strip().upper().replace("-", ":")


def is_private_mac(mac):
    """
    Detect locally administered MAC addresses.
    These are often randomized/private WiFi addresses on phones/laptops.
    """
    try:
        first_octet = int(normalize_mac(mac).split(":")[0], 16)
        return bool(first_octet & 0b00000010)
    except:
        return False


def build_identity_status(mac, network_name, known_macs, network_map):
    mac = normalize_mac(mac)
    if mac not in known_macs:
        return "New MAC", True

    seen_networks = network_map.get(mac, set())
    if network_name and seen_networks and network_name not in seen_networks:
        return "Known MAC / New WiFi", False

    return "Recognized MAC", False


# ─── Known Device Check ───────────────────

def check_if_known(mac, known_macs=None):
    known = known_macs if known_macs is not None else get_known_device_macs()
    return normalize_mac(mac) in known


# ─── Full Scan ────────────────────────────

def run_device_scan():
    raw     = arp_scan()
    results = []
    known_macs = get_known_device_macs()
    network_map = get_device_network_map()
    network_name = get_current_wifi_name() or "(Unknown WiFi)"

    for d in raw:
        ip       = d["ip"]
        mac      = normalize_mac(d["mac"])
        hostname = get_hostname(ip)
        dtype    = guess_device_type(hostname, mac)
        private  = is_private_mac(mac)
        status, is_new = build_identity_status(mac, network_name, known_macs, network_map)

        save_device(ip, mac, hostname, status, network_name, private)
        known_macs.add(mac)
        network_map.setdefault(mac, set()).add(network_name)

        # Alert only for genuinely new MAC identities.
        if is_new:
            generate_device_alert(ip, mac, hostname)

        results.append({
            "ip":       ip,
            "mac":      mac,
            "hostname": hostname,
            "type":     dtype,
            "status":   status,
            "is_new":   is_new,
            "network":  network_name,
            "is_private_mac": private,
            "identity_note": (
                "Private/randomized MAC likely" if private
                else "Stable hardware MAC likely"
            )
        })

    return results

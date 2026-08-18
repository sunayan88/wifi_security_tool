# ─────────────────────────────────────────
#  WiFi Security Tool — ARP Spoof Monitor
#  Detects active Man-in-the-Middle attacks
# ─────────────────────────────────────────

import subprocess
import re
import socket
import threading
import time
from database.db_manager import get_approved_gateway, save_alert
from utils.helpers import get_current_wifi_name


# ─── Gateway Detection ────────────────────

def get_gateway_ip():
    """Gets the default gateway IP address on Windows."""
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, creationflags=0x08000000
        )
        output = result.stdout.decode("utf-8", errors="ignore")

        # Look for Default Gateway in the WiFi adapter section
        matches = re.findall(r"Default Gateway[.\s]+:\s*([\d.]+)", output)
        for ip in matches:
            if not ip.startswith("0.") and ip != "":
                return ip
        return None
    except:
        return None


def get_mac_from_arp_table(ip):
    """
    Looks up the MAC address for a given IP using the Windows ARP table.
    Much faster than a full ARP scan — just reads the cached table.
    """
    try:
        result = subprocess.run(
            ["arp", "-a", ip], capture_output=True, creationflags=0x08000000
        )
        output = result.stdout.decode("utf-8", errors="ignore")

        # ARP table line looks like: 192.168.1.1     aa-bb-cc-dd-ee-ff   dynamic
        match = re.search(
            r"([\d.]+)\s+([0-9a-fA-F\-:]{17})\s+\w+", output
        )
        if match:
            mac = match.group(2).upper().replace("-", ":")
            return mac
        return None
    except:
        return None


def get_mac_via_scapy(ip):
    """
    Sends a live ARP request to get the MAC address.
    More reliable than the ARP table when it hasn't been populated.
    """
    try:
        from scapy.all import ARP, Ether, srp
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        result = srp(packet, timeout=2, verbose=False)[0]
        if result:
            return result[0][1].hwsrc.upper()
        return None
    except:
        return None


def get_gateway_mac(gateway_ip):
    """Tries ARP table first, falls back to live ARP request."""
    mac = get_mac_from_arp_table(gateway_ip)
    if not mac:
        mac = get_mac_via_scapy(gateway_ip)
    return mac


# ─── Gateway Snapshot ─────────────────────

def take_gateway_snapshot():
    """
    Takes a snapshot of the current gateway IP and MAC.
    Returns dict or None if gateway is unreachable.
    """
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        return None

    gateway_mac = get_gateway_mac(gateway_ip)
    if not gateway_mac:
        return None

    return {
        "network": get_current_wifi_name() or "(Unknown network)",
        "ip":  gateway_ip,
        "mac": gateway_mac
    }


# ─── ARP Spoof Check ──────────────────────

def check_arp_spoof(known_snapshot, log_alert=True):
    """
    Compares the current gateway MAC against a known trusted snapshot.

    Returns dict with:
      - status: 'safe' | 'spoofed' | 'unreachable'
      - current_ip
      - current_mac
      - known_mac
      - message
    """
    if not known_snapshot:
        return {
            "status":      "unreachable",
            "current_ip":  None,
            "current_mac": None,
            "known_mac":   None,
            "message":     "No gateway snapshot available to compare against."
        }

    known_ip      = known_snapshot["ip"]
    known_mac     = known_snapshot["mac"]
    known_network = known_snapshot.get("network")

    current_snapshot = take_gateway_snapshot()
    if not current_snapshot:
        return {
            "status":      "unreachable",
            "current_ip":  known_ip,
            "current_mac": None,
            "known_mac":   known_mac,
            "message":     "Could not reach gateway. You may be disconnected."
        }

    current_ip      = current_snapshot["ip"]
    current_mac     = current_snapshot["mac"]
    current_network = current_snapshot.get("network")

    if current_ip != known_ip:
        if log_alert:
            save_alert(
                "DEVICE",
                f"Gateway IP changed on '{known_network}': expected {known_ip} "
                f"({known_mac}), current {current_ip} ({current_mac}). Verify router/DHCP."
            )
        return {
            "status":      "spoofed",
            "current_ip":  current_ip,
            "current_mac": current_mac,
            "known_mac":   known_mac,
            "message": (
                f"SECURITY WARNING: Default gateway IP changed from {known_ip} "
                f"to {current_ip}. This can be a normal DHCP/router change, but "
                f"it can also indicate a fake gateway. Verify before sensitive use."
            )
        }

    if current_mac.upper() == known_mac.upper():
        return {
            "status":      "safe",
            "current_ip":  known_ip,
            "current_mac": current_mac,
            "known_mac":   known_mac,
            "message":     f"Gateway is legitimate. MAC: {current_mac}"
        }

    # A changed MAC is suspicious, but can also be caused by legitimate
    # router replacement, failover, or network reconfiguration.
    if log_alert:
        save_alert(
            "DEVICE",
            f"Gateway identity changed: {known_ip} changed MAC from "
            f"{known_mac} to {current_mac} on '{current_network}'. "
            "Verify the router before continuing."
        )

    return {
        "status":      "spoofed",
        "current_ip":  known_ip,
        "current_mac": current_mac,
        "known_mac":   known_mac,
        "message": (
            f"SECURITY WARNING: Your gateway ({known_ip}) is now "
            f"responding from a different MAC address ({current_mac}). "
            f"Expected: {known_mac}. This can indicate ARP spoofing, but a "
            f"legitimate router or network change can cause it too."
        )
    }


# ─── Background Monitor ───────────────────

class ARPMonitor:
    """
    Background thread that continuously monitors gateway MAC
    and calls a callback when a spoof is detected.
    """

    def __init__(self, on_alert, interval_seconds=30):
        self.on_alert        = on_alert
        self.interval        = interval_seconds
        self.running         = False
        self.thread          = None
        self._stop_event     = threading.Event()
        self.known_snapshot  = None
        self.last_result     = None
        self.observed_snapshot = None

    def start(self):
        """Takes initial snapshot and starts the background monitor."""
        if self.running:
            return False, "Gateway monitoring is already running."
        self.observed_snapshot = take_gateway_snapshot()
        if not self.observed_snapshot:
            return False, "Could not detect gateway. Make sure you are connected to WiFi."

        self.known_snapshot = get_approved_gateway(
            self.observed_snapshot["network"],
            self.observed_snapshot["ip"],
        )
        if not self.known_snapshot:
            return (
                False,
                "This gateway has not been approved yet. Verify its IP and MAC, "
                "then choose Approve Gateway.",
            )

        self.running = True
        self._stop_event.clear()
        self.thread  = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True, f"Monitoring gateway {self.known_snapshot['ip']} ({self.known_snapshot['mac']})"

    def stop(self):
        self.running = False
        self._stop_event.set()

    def get_snapshot(self):
        return self.known_snapshot

    def get_observed_snapshot(self):
        return self.observed_snapshot

    def get_last_result(self):
        return self.last_result

    def _loop(self):
        suspicious_count = 0
        alerted = False
        while self.running:
            result           = check_arp_spoof(self.known_snapshot, log_alert=False)
            self.last_result = result

            if result["status"] == "spoofed":
                suspicious_count += 1
            else:
                suspicious_count = 0
                alerted = False

            if (
                result["status"] == "spoofed"
                and suspicious_count >= 2
                and not alerted
            ):
                save_alert(
                    "DEVICE",
                    f"Gateway identity changed: {result['current_ip']} changed MAC "
                    f"from {result['known_mac']} to {result['current_mac']}."
                )
                self.on_alert(result)
                alerted = True
            self._stop_event.wait(self.interval)

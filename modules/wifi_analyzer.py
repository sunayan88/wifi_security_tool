# ─────────────────────────────────────────
#  WiFi Security Tool — WiFi Analyzer
#  With BSSID Trust Memory (Evil Twin Defense)
# ─────────────────────────────────────────

import subprocess
import re
from config import RISK_SAFE, RISK_RISKY, RISK_DANGEROUS
from database.db_manager import (
    save_wifi_scan, save_alert,
    get_trust_status, get_trusted_bssids, add_trusted_bssid
)
from modules.alert_system import generate_wifi_alert


def explain_netsh_error(output):
    """Return a user-friendly explanation when Windows blocks WLAN commands."""
    lower = (output or "").lower()
    messages = []

    if "location permission" in lower or "location services" in lower:
        messages.append(
            "Windows blocked WiFi network scanning because Location services are off. "
            "Open Settings > Privacy & security > Location and allow Location services."
        )

    if (
        "requires elevation" in lower
        or "error 5" in lower
        or "access is denied" in lower
    ):
        messages.append("Run this app as Administrator so Windows allows WLAN scan access.")

    if "wireless autoconfig service" in lower or "wlansvc" in lower:
        messages.append("Make sure the Windows WLAN AutoConfig service is running.")

    if messages:
        return " ".join(messages)
    return None


def run_netsh(args):
    try:
        result = subprocess.run(
            ["netsh"] + args, capture_output=True, creationflags=0x08000000
        )
        raw_output = (result.stdout or b"") + b"\n" + (result.stderr or b"")
        try:
            return raw_output.decode("utf-8")
        except:
            return raw_output.decode("cp1252", errors="ignore")
    except Exception:
        return ""


def get_band_from_channel(channel):
    """Determines 2.4GHz / 5GHz / 6GHz band from the WiFi channel number."""
    try:
        ch = int(str(channel).strip())
    except:
        return "Unknown"

    if 1 <= ch <= 14:
        return "2.4 GHz"
    if 32 <= ch <= 68:
        return "5 GHz"
    if 100 <= ch <= 177:
        return "5 GHz"
    if ch >= 1 and ch in range(1, 234) and ch > 177:
        return "6 GHz"
    return "Unknown"


def classify_security(authentication, encryption=""):
    """Classify visible WiFi authentication/cipher strength without reading passwords."""
    auth = (authentication or "").upper()
    cipher = (encryption or "").upper()

    if any(w in auth for w in ["OPEN", "NONE"]) or "WEP" in auth:
        return {
            "label": "Dangerous",
            "risk": RISK_DANGEROUS,
            "message": "Open/None/WEP security is unsafe. Avoid sensitive activity.",
        }

    if "WPA3" in auth:
        return {
            "label": "Stronger",
            "risk": RISK_SAFE,
            "message": (
                "WPA3 is the strongest common personal WiFi security. This protects "
                "the wireless link, but websites/network operators still matter."
            ),
        }

    if "WPA2" in auth:
        if "TKIP" in cipher:
            return {
                "label": "Risky",
                "risk": RISK_RISKY,
                "message": "WPA2 with TKIP is outdated. Prefer WPA2/WPA3 with AES/CCMP.",
            }
        return {
            "label": "Safer",
            "risk": RISK_SAFE,
            "message": (
                "WPA2 with modern cipher is generally safe for the wireless link, "
                "but password strength cannot be verified without user input."
            ),
        }

    if "WPA" in auth:
        return {
            "label": "Risky",
            "risk": RISK_RISKY,
            "message": "Older WPA is outdated. Prefer WPA2-AES or WPA3.",
        }

    return {
        "label": "Unknown",
        "risk": RISK_RISKY,
        "message": f"Security type '{authentication or 'Unknown'}' is unclear. Proceed with caution.",
    }


def detect_wps_from_text(text):
    """Best-effort WPS detection from netsh-visible text."""
    lower = (text or "").lower()
    if "wps" not in lower:
        return "Unknown"
    if re.search(r"wps[^\n\r:]*:\s*(yes|enabled|configured|supported)", lower):
        return "Enabled / Visible"
    if re.search(r"wps[^\n\r:]*:\s*(no|disabled|not configured|not supported)", lower):
        return "Disabled / Not visible"
    return "Mentioned"


def get_current_network():
    output = run_netsh(["wlan", "show", "interfaces"])

    if not output or len(output.strip()) < 10:
        return {"error": "netsh returned no output. Make sure WiFi adapter is enabled."}

    access_error = explain_netsh_error(output)
    if access_error:
        return {"error": access_error}

    data     = {}
    patterns = {
        "ssid":           r"SSID\s*:\s*(.+)",
        "bssid":          r"BSSID\s*:\s*(.+)",
        "signal":         r"Signal\s*:\s*(.+)",
        "authentication": r"Authentication\s*:\s*(.+)",
        "encryption":     r"Cipher\s*:\s*(.+)",
        "state":          r"State\s*:\s*(.+)",
        "channel":        r"Channel\s*:\s*(.+)",
        "radio_type":     r"Radio type\s*:\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, output)
        if key == "ssid" and matches:
            candidates = [m.strip() for m in matches if len(m.strip()) < 60]
            data[key]  = candidates[0] if candidates else "Unknown"
        elif matches:
            data[key] = matches[0].strip()
        else:
            data[key] = "Unknown"

    data["band"] = get_band_from_channel(data.get("channel", "Unknown"))
    classification = classify_security(
        data.get("authentication", "Unknown"),
        data.get("encryption", "Unknown"),
    )
    data["security_strength"] = classification["label"]
    data["wps"] = detect_wps_from_text(output)

    if data.get("state", "").lower() in ["", "unknown"]:
        data["error"] = "Could not read state. Try running as Administrator."

    return data


def analyze_risk(network_info):
    if "error" in network_info:
        return RISK_DANGEROUS, f"Error: {network_info['error']}"

    state = network_info.get("state", "").lower()

    if "disconnected" in state:
        return RISK_DANGEROUS, "You are not connected to any WiFi network."

    classification = classify_security(
        network_info.get("authentication", ""),
        network_info.get("encryption", ""),
    )
    return classification["risk"], classification["message"]


def scan_nearby_networks():
    """
    Parses 'netsh wlan show networks mode=bssid' output.

    Two important fixes baked in:
    1. We split only on lines that START with 'SSID <number>' — the literal
       substring 'SSID' inside 'BSSID' was previously causing bad splits.
    2. The whitespace right after the SSID colon is restricted to spaces/tabs
       only (not '\\s*', which also matches newlines). For hidden networks
       with a blank SSID name, '\\s*' was swallowing the newline and capturing
       the NEXT line ('Network type : Infrastructure') as if it were the name.
    """
    output   = run_netsh(["wlan", "show", "networks", "mode=bssid"])
    networks = []
    if not output:
        return networks, "netsh returned no nearby-network data. Make sure WiFi is enabled."

    access_error = explain_netsh_error(output)
    if access_error:
        return networks, access_error

    blocks = re.split(r"(?m)(?=^SSID\s+\d+[ \t]*:)", output)

    for block in blocks:
        ssid_m = re.search(r"(?m)^SSID\s+\d+[ \t]*:[ \t]*(.*)$", block)
        if not ssid_m:
            continue

        ssid_name = ssid_m.group(1).strip()
        if not ssid_name:
            ssid_name = "(Hidden Network)"

        auth_m = re.search(r"(?m)^\s*Authentication\s*:\s*(.+)$", block)
        auth   = auth_m.group(1).strip() if auth_m else "Unknown"
        cipher_m = re.search(r"(?m)^\s*(?:Encryption|Cipher)\s*:\s*(.+)$", block)
        cipher = cipher_m.group(1).strip() if cipher_m else "Unknown"
        classification = classify_security(auth, cipher)
        wps = detect_wps_from_text(block)
        is_open = any(w in auth.upper() for w in ["OPEN", "NONE"])

        bssid_entries   = re.findall(r"(?m)^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]+)", block)
        signal_entries  = re.findall(r"(?m)^\s*Signal\s*:\s*(\d+%)", block)
        channel_entries = re.findall(r"(?m)^\s*Channel\s*:\s*(\d+)", block)

        if bssid_entries:
            for i, bssid in enumerate(bssid_entries):
                signal  = signal_entries[i]  if i < len(signal_entries)  else "Unknown"
                channel = channel_entries[i] if i < len(channel_entries) else "Unknown"
                networks.append({
                    "ssid":           ssid_name,
                    "bssid":          bssid.strip(),
                    "authentication": auth,
                    "encryption":      cipher,
                    "security_strength": classification["label"],
                    "wps":             wps,
                    "signal":         signal,
                    "channel":        channel,
                    "band":           get_band_from_channel(channel),
                    "is_open":        is_open
                })
        else:
            networks.append({
                "ssid":           ssid_name,
                "bssid":          "Unknown",
                "authentication": auth,
                "encryption":      cipher,
                "security_strength": classification["label"],
                "wps":             wps,
                "signal":         "Unknown",
                "channel":        "Unknown",
                "band":           "Unknown",
                "is_open":        is_open
            })

    return networks, None


def detect_fake_networks(current_ssid, nearby):
    return [
        {
            "ssid":   n["ssid"],
            "bssid":  n["bssid"],
            "reason": "Same name as your network but unsecured — possible fake hotspot."
        }
        for n in nearby
        if n["ssid"] == current_ssid and n["is_open"]
    ]


def disconnect_wifi():
    """Disconnects from the current WiFi network."""
    try:
        subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, creationflags=0x08000000)
        return True, "Disconnected from WiFi."
    except Exception as e:
        return False, str(e)


def run_wifi_scan():
    network      = get_current_network()
    risk, reason = analyze_risk(network)
    nearby, nearby_error = scan_nearby_networks()
    fakes        = detect_fake_networks(network.get("ssid", ""), nearby)

    if nearby_error:
        reason = f"{reason} Nearby network scan blocked: {nearby_error}"

    current_ssid  = network.get("ssid", "Unknown")
    current_bssid = network.get("bssid", "Unknown")

    for n in nearby:
        if (
            n.get("bssid", "").lower() == str(current_bssid).lower()
            or n.get("ssid") == current_ssid
        ):
            if network.get("wps", "Unknown") == "Unknown":
                network["wps"] = n.get("wps", "Unknown")
            network["security_strength"] = n.get(
                "security_strength",
                network.get("security_strength", "Unknown"),
            )
            break

    if network.get("wps") in {"Enabled / Visible", "Mentioned"}:
        if risk == RISK_SAFE:
            risk = RISK_RISKY
        reason = (
            f"{reason} WPS appears to be enabled/visible; disable WPS on the router "
            "if possible because it can weaken WiFi security."
        )

    trust_status = get_trust_status(current_ssid, current_bssid)

    for n in nearby:
        n["trust_status"] = get_trust_status(n["ssid"], n["bssid"])

    if trust_status == "mismatch":
        risk   = RISK_DANGEROUS
        reason = (
            f"SECURITY ALERT: '{current_ssid}' is being served by a DIFFERENT router "
            f"than the one you approved. This may be a changed router, mesh access point, "
            f"or an evil twin. Verify the router before entering sensitive information."
        )
        save_alert(
            "WIFI",
            f"BSSID mismatch for trusted network '{current_ssid}'. "
            f"Unrecognized router: {current_bssid}"
        )

    save_wifi_scan(
        ssid       = current_ssid,
        security   = network.get("authentication", "Unknown"),
        risk_level = risk
    )
    generate_wifi_alert(risk, current_ssid)

    return {
        "network":        network,
        "risk":           risk,
        "reason":         reason,
        "nearby":         nearby,
        "nearby_error":   nearby_error,
        "fakes":          fakes,
        "trust_status":   trust_status,
        "trusted_bssids": get_trusted_bssids(current_ssid),
    }

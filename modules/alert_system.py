# ─────────────────────────────────────────
#  WiFi Security Tool — Alert System
#  Module 4: Manages and generates alerts
# ─────────────────────────────────────────

from database.db_manager import save_alert, get_recent_alerts
from config import RISK_SAFE, RISK_RISKY, RISK_DANGEROUS


ALERT_TYPES = {
    "WIFI":     "WiFi Security",
    "DEVICE":   "Device Monitor",
    "SYSTEM":   "System"
}


def generate_wifi_alert(risk, ssid):
    """Generates and saves a WiFi-related alert."""
    if risk == RISK_DANGEROUS:
        msg = f"DANGER: Network '{ssid}' is open or poorly secured. Avoid sensitive activity."
    elif risk == RISK_RISKY:
        msg = f"WARNING: Network '{ssid}' uses outdated security. Use with caution."
    else:
        return  # No alert needed for safe networks

    save_alert("WIFI", msg)
    return msg


def generate_device_alert(ip, mac, hostname):
    """Generates and saves an alert for a new unknown device."""
    msg = f"Unknown device detected — IP: {ip} | MAC: {mac} | Hostname: {hostname}"
    save_alert("DEVICE", msg)
    return msg


def get_all_alerts():
    """
    Fetches all recent alerts from DB and formats them for UI.
    Returns list of dicts.
    """
    raw     = get_recent_alerts(limit=100)
    results = []

    for row in raw:
        # row = (id, alert_type, message, logged_at)
        alert_type = row[1]
        results.append({
            "id":         row[0],
            "type":       alert_type,
            "type_label": ALERT_TYPES.get(alert_type, alert_type),
            "message":    row[2],
            "time":       row[3]
        })

    return results


def get_alert_color(alert_type):
    """Returns color for each alert type."""
    colors = {
        "WIFI":     "#f39c12",
        "DEVICE":   "#e74c3c",
        "SYSTEM":   "#3498db"
    }
    return colors.get(alert_type, "#888888")

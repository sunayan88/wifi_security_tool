# ─────────────────────────────────────────
#  WiFi Security Tool — Configuration
# ─────────────────────────────────────────

import os

# App Info
APP_NAME    = "WiFi Security Monitor"
APP_VERSION = "1.0.0"

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database", "wifi_security.db")

# Scanning
SCAN_INTERVAL_SECONDS = 30
ARP_TIMEOUT           = 3
NMAP_TIMEOUT          = 10

# Local data retention (newest records are kept)
MAX_DEVICE_HISTORY = 2000
MAX_WIFI_SCAN_HISTORY = 500
MAX_ALERT_HISTORY = 1000

# Risk Levels
RISK_SAFE      = "SAFE"
RISK_RISKY     = "RISKY"
RISK_DANGEROUS = "DANGEROUS"

# WiFi Security
WEAK_SECURITY_TYPES = ["WEP", "OPEN", "NONE"]

# Colors (used in logic, not UI — CTk handles UI colors)
COLOR_SAFE      = "#2ecc71"
COLOR_RISKY     = "#f39c12"
COLOR_DANGEROUS = "#e74c3c"

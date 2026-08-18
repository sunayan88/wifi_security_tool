# ─────────────────────────────────────────
#  WiFi Security Tool — Database Manager
# ─────────────────────────────────────────

import sqlite3
import bcrypt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    DB_PATH,
    MAX_ALERT_HISTORY,
    MAX_DEVICE_HISTORY,
    MAX_WIFI_SCAN_HISTORY,
)
from utils.helpers import timestamp


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def initialize_db():
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password     TEXT NOT NULL,
            hash_version TEXT NOT NULL DEFAULT 'bcrypt',
            created_at   TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT,
            mac       TEXT,
            hostname  TEXT,
            status    TEXT,
            network_name TEXT,
            is_private_mac INTEGER DEFAULT 0,
            seen_at   TEXT
        )
    """)

    # ── NEW: Custom device labels keyed by MAC ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_labels (
            mac        TEXT PRIMARY KEY,
            label      TEXT NOT NULL,
            updated_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wifi_scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid       TEXT,
            security   TEXT,
            risk_level TEXT,
            scanned_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            message    TEXT,
            logged_at  TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_networks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid        TEXT NOT NULL,
            bssid       TEXT NOT NULL,
            first_seen  TEXT,
            last_seen   TEXT,
            trust_count INTEGER DEFAULT 1,
            UNIQUE(ssid, bssid)
        )
    """)

    # ── NEW: Gateway history for ARP monitor ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gateway_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            gw_ip       TEXT,
            gw_mac      TEXT,
            recorded_at TEXT
        )
    """)

    # Discard the short-lived IP-only baseline schema. An IP such as
    # 192.168.1.1 is not a safe identity across different WiFi networks.
    cursor.execute("PRAGMA table_info(trusted_gateways)")
    gateway_columns = {column[1] for column in cursor.fetchall()}
    if gateway_columns and "network_name" not in gateway_columns:
        cursor.execute("DROP TABLE trusted_gateways")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_gateways (
            network_name TEXT NOT NULL,
            gw_ip       TEXT NOT NULL,
            gw_mac      TEXT NOT NULL,
            approved_at TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            PRIMARY KEY (network_name, gw_ip)
        )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_mac_seen ON devices(mac, seen_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_logged_at ON alerts(logged_at)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_wifi_scans_scanned_at ON wifi_scans(scanned_at)"
    )

    # Migration — add hash_version column if missing
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if "hash_version" not in columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN hash_version TEXT NOT NULL DEFAULT 'sha256_legacy'"
        )

    cursor.execute("PRAGMA table_info(devices)")
    device_columns = [col[1] for col in cursor.fetchall()]
    if "network_name" not in device_columns:
        cursor.execute("ALTER TABLE devices ADD COLUMN network_name TEXT")
    if "is_private_mac" not in device_columns:
        cursor.execute("ALTER TABLE devices ADD COLUMN is_private_mac INTEGER DEFAULT 0")

    _migrate_sha256_users(cursor)
    conn.commit()
    conn.close()


def _migrate_sha256_users(cursor):
    try:
        cursor.execute("SELECT id, password, hash_version FROM users")
        for uid, pwd, version in cursor.fetchall():
            if version == "bcrypt":
                continue
            if len(pwd) == 64 and all(c in "0123456789abcdef" for c in pwd):
                cursor.execute(
                    "UPDATE users SET hash_version = 'sha256_legacy' WHERE id = ?", (uid,)
                )
    except:
        pass


# ─── Password ─────────────────────────────

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain, stored, version="bcrypt"):
    try:
        if version == "bcrypt":
            return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
        elif version == "sha256_legacy":
            import hashlib
            return hashlib.sha256(plain.encode()).hexdigest() == stored
        return False
    except:
        return False


# ─── Auth ─────────────────────────────────

def register_user(username, password):
    username = username.strip()
    if not username or not password:
        return False, "Username and password cannot be empty."
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, hash_version, created_at) VALUES (?,?,'bcrypt',?)",
            (username, hash_password(password), timestamp())
        )
        conn.commit()
        conn.close()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists. Please choose another."
    except Exception as e:
        return False, f"Error: {str(e)}"


def login_user(username, password):
    if not username or not password:
        return False, "Please enter your username and password."
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password, hash_version FROM users WHERE username = ?",
            (username.strip(),)
        )
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False, "Incorrect username or password."
        uid, uname, stored, version = user
        if not verify_password(password, stored, version):
            conn.close()
            return False, "Incorrect username or password."
        if version == "sha256_legacy":
            cursor.execute(
                "UPDATE users SET password=?, hash_version='bcrypt' WHERE id=?",
                (hash_password(password), uid)
            )
            conn.commit()
        conn.close()
        return True, (uid, uname)
    except Exception as e:
        return False, f"Error: {str(e)}"


# ─── Devices ──────────────────────────────

def save_device(ip, mac, hostname, status, network_name=None, is_private_mac=False):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO devices "
        "(ip, mac, hostname, status, network_name, is_private_mac, seen_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (ip, mac, hostname, status, network_name, 1 if is_private_mac else 0, timestamp())
    )
    _keep_newest(cursor, "devices", MAX_DEVICE_HISTORY)
    conn.commit()
    conn.close()


def get_all_devices():
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY seen_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_known_device_macs():
    """Return normalized MAC addresses previously observed or labeled."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT UPPER(mac) FROM devices WHERE mac IS NOT NULL
        UNION
        SELECT DISTINCT UPPER(mac) FROM device_labels WHERE mac IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()
    return {row[0] for row in rows}


def get_device_network_map():
    """Return {MAC: set(network names)} for prior observations."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT UPPER(mac), COALESCE(network_name, '')
        FROM devices
        WHERE mac IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()
    result = {}
    for mac, network in rows:
        result.setdefault(mac, set())
        if network:
            result[mac].add(network)
    return result


# ─── Device Labels (Persistent Naming) ────

def set_device_label(mac, label):
    """Set or update a friendly name for a device MAC address."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO device_labels (mac, label, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            label      = excluded.label,
            updated_at = excluded.updated_at
    """, (mac.strip().upper(), label.strip(), timestamp()))
    conn.commit()
    conn.close()


def get_device_label(mac):
    """Returns the custom label for a MAC, or None."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT label FROM device_labels WHERE mac = ?", (mac.strip().upper(),))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def get_all_device_labels():
    """Returns all labels as a dict: {mac: label}"""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT mac, label FROM device_labels")
    rows = cursor.fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}


def delete_device_label(mac):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM device_labels WHERE mac = ?", (mac.strip().upper(),))
    conn.commit()
    conn.close()


# ─── WiFi / Alerts ────────────────────────

def save_wifi_scan(ssid, security, risk_level):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO wifi_scans (ssid, security, risk_level, scanned_at) VALUES (?,?,?,?)",
        (ssid, security, risk_level, timestamp())
    )
    _keep_newest(cursor, "wifi_scans", MAX_WIFI_SCAN_HISTORY)
    conn.commit()
    conn.close()


def save_alert(alert_type, message):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (alert_type, message, logged_at) VALUES (?,?,?)",
        (alert_type, message, timestamp())
    )
    _keep_newest(cursor, "alerts", MAX_ALERT_HISTORY)
    conn.commit()
    conn.close()


def get_recent_alerts(limit=100):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY logged_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def _keep_newest(cursor, table, limit):
    """Bound append-only history tables to their configured newest rows."""
    allowed = {"devices", "wifi_scans", "alerts"}
    if table not in allowed:
        raise ValueError("Unsupported retention table")
    cursor.execute(
        f"DELETE FROM {table} WHERE id NOT IN "
        f"(SELECT id FROM {table} ORDER BY id DESC LIMIT ?)",
        (limit,),
    )


# ─── BSSID Trust Memory ───────────────────

def _norm(bssid):
    return bssid.strip().upper().replace("-", ":")


def add_trusted_bssid(ssid, bssid):
    if not ssid or ssid == "Unknown":
        return
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO trusted_networks (ssid, bssid, first_seen, last_seen, trust_count)
        VALUES (?,?,?,?,1)
        ON CONFLICT(ssid, bssid) DO UPDATE SET
            last_seen   = excluded.last_seen,
            trust_count = trust_count + 1
    """, (ssid, _norm(bssid), timestamp(), timestamp()))
    conn.commit()
    conn.close()


def get_trusted_bssids(ssid):
    if not ssid or ssid == "Unknown":
        return []
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT bssid FROM trusted_networks WHERE ssid = ?", (ssid,))
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]


def get_trust_status(ssid, bssid):
    if not ssid or ssid == "Unknown" or not bssid or bssid == "Unknown":
        return "unknown"
    trusted = get_trusted_bssids(ssid)
    if not trusted:
        return "new"
    return "trusted" if _norm(bssid) in trusted else "mismatch"


def remove_trust(ssid, bssid):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM trusted_networks WHERE ssid=? AND bssid=?", (ssid, _norm(bssid))
    )
    conn.commit()
    conn.close()


# ─── Gateway History ──────────────────────

def save_gateway_entry(gw_ip, gw_mac):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO gateway_history (gw_ip, gw_mac, recorded_at) VALUES (?,?,?)",
        (gw_ip, gw_mac, timestamp())
    )
    conn.commit()
    conn.close()


def approve_gateway(network_name, gw_ip, gw_mac):
    """Store a gateway identity only after explicit user approval."""
    now = timestamp()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO trusted_gateways
            (network_name, gw_ip, gw_mac, approved_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(network_name, gw_ip) DO UPDATE SET
            gw_mac = excluded.gw_mac,
            updated_at = excluded.updated_at
    """, (network_name, gw_ip, _norm(gw_mac), now, now))
    conn.commit()
    conn.close()


def get_approved_gateway(network_name, gw_ip):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT network_name, gw_ip, gw_mac, approved_at "
        "FROM trusted_gateways WHERE network_name = ? AND gw_ip = ?",
        (network_name, gw_ip),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "network": row[0],
        "ip": row[1],
        "mac": row[2],
        "approved_at": row[3],
    }


def clear_activity_history():
    """Delete observations while preserving users, labels, and trust choices."""
    conn = get_connection()
    cursor = conn.cursor()
    counts = {}
    for table in ("devices", "wifi_scans", "alerts", "gateway_history"):
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        counts[table] = cursor.fetchone()[0]
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
    return counts


def clear_trust_data():
    """Delete WiFi and gateway approvals without deleting user accounts."""
    conn = get_connection()
    cursor = conn.cursor()
    counts = {}
    for table in ("trusted_networks", "trusted_gateways"):
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        counts[table] = cursor.fetchone()[0]
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
    return counts


def get_privacy_counts():
    conn = get_connection()
    cursor = conn.cursor()
    result = {}
    for table in (
        "devices", "wifi_scans", "alerts", "device_labels",
        "trusted_networks", "trusted_gateways",
    ):
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        result[table] = cursor.fetchone()[0]
    conn.close()
    return result

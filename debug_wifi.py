# ─────────────────────────────────────────
#  DEBUG SCRIPT — Run this to check netsh
#  python debug_wifi.py
# ─────────────────────────────────────────

import subprocess

print("=" * 60)
print("INTERFACES OUTPUT:")
print("=" * 60)

try:
    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True
    )
    try:
        out = result.stdout.decode("utf-8")
    except:
        out = result.stdout.decode("cp1252", errors="ignore")
    print(out)
except Exception as e:
    print(f"ERROR: {e}")

print("=" * 60)
print("NEARBY NETWORKS OUTPUT:")
print("=" * 60)

try:
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True
    )
    try:
        out = result.stdout.decode("utf-8")
    except:
        out = result.stdout.decode("cp1252", errors="ignore")
    print(out)
except Exception as e:
    print(f"ERROR: {e}")
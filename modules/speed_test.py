# ─────────────────────────────────────────
#  WiFi Security Tool — Network Speed Test
# ─────────────────────────────────────────

import time
import requests


def measure_ping(url="https://www.cloudflare.com", attempts=3):
    """Measures round-trip latency in milliseconds."""
    times = []
    for _ in range(attempts):
        try:
            start = time.time()
            requests.head(url, timeout=5)
            times.append((time.time() - start) * 1000)
        except Exception:
            pass
    return round(sum(times) / len(times), 1) if times else None


def measure_download_speed(test_size_bytes=8_000_000):
    """
    Downloads a test payload from Cloudflare's public speed-test endpoint
    and measures effective throughput in Mbps.
    """
    url = "https://speed.cloudflare.com/__down"
    try:
        start      = time.time()
        response   = requests.get(url, params={"bytes": test_size_bytes}, stream=True, timeout=20)
        downloaded = 0
        for chunk in response.iter_content(chunk_size=65536):
            downloaded += len(chunk)
            if downloaded >= test_size_bytes:
                break
        elapsed = time.time() - start

        if elapsed <= 0 or downloaded == 0:
            return None

        mbps = (downloaded * 8) / (elapsed * 1_000_000)
        return round(mbps, 2)
    except Exception:
        return None


def run_speed_test():
    """
    Runs a basic ping + download speed test.
    Returns a dict with results, or None values if the test failed.
    """
    ping     = measure_ping()
    download = measure_download_speed()

    return {
        "ping_ms":       ping,
        "download_mbps": download
    }
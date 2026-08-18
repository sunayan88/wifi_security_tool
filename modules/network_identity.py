import os
import requests


IPINFO_LITE_URL = "https://api.ipinfo.io/lite/me"
TOKEN_ENV_VAR = "IPINFO_TOKEN"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = os.path.join(BASE_DIR, "ipinfo_token.txt")


def _clean(value):
    return str(value).strip() if value not in (None, "") else "Unknown"


def _read_token_file():
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def get_ipinfo_token():
    """Prefer environment variable, then fall back to local token file."""
    return os.environ.get(TOKEN_ENV_VAR, "").strip() or _read_token_file()


def check_network_identity():
    """
    Looks up the current public network identity using IPinfo Lite.

    IPinfo Lite is country/ASN focused. It can identify the public IP,
    ASN, operator name, and country, but it should not be treated as exact
    physical router location.
    """
    token = get_ipinfo_token()
    if not token:
        return {
            "status": "missing_token",
            "message": (
                f"Missing IPinfo token. Set {TOKEN_ENV_VAR} or paste your token "
                "into ipinfo_token.txt, then restart the app."
            ),
        }

    try:
        response = requests.get(
            IPINFO_LITE_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=8,
        )
    except requests.RequestException as exc:
        return {
            "status": "error",
            "message": f"Could not contact IPinfo: {exc}",
        }

    if response.status_code == 401:
        return {
            "status": "error",
            "message": "IPinfo rejected the token. Regenerate/check your token.",
        }

    if response.status_code == 429:
        return {
            "status": "error",
            "message": "IPinfo rate limit reached. Try again later.",
        }

    if not response.ok:
        return {
            "status": "error",
            "message": f"IPinfo returned HTTP {response.status_code}.",
        }

    try:
        data = response.json()
    except ValueError:
        return {
            "status": "error",
            "message": "IPinfo returned an invalid response.",
        }

    ip = _clean(data.get("ip"))
    asn = _clean(data.get("asn"))
    as_name = _clean(data.get("as_name") or data.get("org"))
    as_domain = _clean(data.get("as_domain"))
    country = _clean(data.get("country") or data.get("country_name"))
    country_code = _clean(data.get("country_code"))
    continent = _clean(data.get("continent") or data.get("continent_code"))

    location_parts = []
    if country != "Unknown":
        location_parts.append(country)
    if country_code != "Unknown" and country_code != country:
        location_parts.append(country_code)
    if continent != "Unknown":
        location_parts.append(continent)

    return {
        "status": "ok",
        "public_ip": ip,
        "asn": asn,
        "isp": as_name,
        "as_domain": as_domain,
        "country": country,
        "country_code": country_code,
        "continent": continent,
        "location": ", ".join(location_parts) if location_parts else "Unknown",
        "message": (
            "Public network identity retrieved. Location is approximate and "
            "country-level on IPinfo Lite."
        ),
    }

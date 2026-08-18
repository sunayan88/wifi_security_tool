"""Captive portal detection using well-known connectivity probes."""

import requests


PROBE_URLS = [
    {
        "url": "http://connectivitycheck.gstatic.com/generate_204",
        "status": 204,
        "body": None,
    },
    {
        "url": "http://www.msftconnecttest.com/connecttest.txt",
        "status": 200,
        "body": "Microsoft Connect Test",
    },
    {
        "url": "http://captive.apple.com/hotspot-detect.html",
        "status": 200,
        "body": "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    },
]


def _is_expected_response(response, probe):
    if response.status_code != probe["status"]:
        return False
    expected_body = probe["body"]
    if expected_body is None:
        return not response.content
    return response.text.strip() == expected_body


def check_portal(timeout=5):
    """
    Detect interception of standard connectivity probes.

    A portal is reported only when a server responds but redirects the request
    or replaces the expected response. Total probe failure is kept separate.
    """
    failures = []

    for probe in PROBE_URLS:
        url = probe["url"]
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "WiFiSecurityTool/1.0"},
            )

            if _is_expected_response(response, probe):
                return {
                    "status": "online",
                    "message": "Connectivity probe returned its expected response.",
                    "portal_url": None,
                    "evidence": url,
                }

            if response.is_redirect:
                destination = response.headers.get("Location", "unknown")
                return {
                    "status": "captive_portal",
                    "message": (
                        "A connectivity probe was redirected. This commonly means "
                        "the network requires a sign-in page; it does not by itself "
                        "prove the page is malicious."
                    ),
                    "portal_url": destination,
                    "evidence": f"{url} redirected to {destination}",
                }

            return {
                "status": "captive_portal",
                "message": (
                    "A connectivity probe was replaced with unexpected content. "
                    "A captive portal or filtering proxy may be intercepting traffic."
                ),
                "portal_url": None,
                "evidence": f"{url} returned HTTP {response.status_code}",
            }
        except (requests.ConnectionError, requests.Timeout) as exc:
            failures.append(f"{url}: {type(exc).__name__}")
        except requests.RequestException as exc:
            failures.append(f"{url}: {type(exc).__name__}")

    return {
        "status": "no_internet",
        "message": "No connectivity probe could be reached.",
        "portal_url": None,
        "evidence": "; ".join(failures),
    }

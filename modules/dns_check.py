"""DNS consistency checks with cautious, evidence-based results."""

import requests
import socket


TEST_DOMAINS = ["www.google.com", "www.cloudflare.com", "www.microsoft.com"]
DOH_RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}


def _query_system(domain):
    try:
        return sorted({
            item[4][0]
            for item in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
            if "." in item[4][0]
        })
    except OSError:
        return None


def _query_doh(resolver_name, domain, timeout=5):
    """
    Resolve A records through DNS-over-HTTPS.

    DoH provides an authenticated HTTPS channel to the reference resolver, which
    is stronger than plaintext UDP DNS on a hostile local network. This still
    remains an indicator, not absolute proof, because CDN/geolocation answers
    can legitimately differ.
    """
    url = DOH_RESOLVERS[resolver_name]
    try:
        response = requests.get(
            url,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        if not response.ok:
            return None
        data = response.json()
    except (requests.RequestException, ValueError, KeyError):
        return None

    if data.get("Status") not in (0, None):
        return []

    answers = data.get("Answer", []) or []
    ips = [
        item.get("data", "")
        for item in answers
        if item.get("type") == 1 and isinstance(item.get("data"), str)
    ]
    return sorted({ip for ip in ips if "." in ip})


def check_dns_integrity():
    """
    Compare the configured system resolver with DNS-over-HTTPS references.

    Different CDN answers are treated as inconclusive. A suspicious result
    requires DoH references to agree while the system answer is disjoint.
    This is still an indicator, not proof of DNS hijacking.
    """
    findings = []
    suspicious_count = 0

    for domain in TEST_DOMAINS:
        system_ips = _query_system(domain)
        ips_a = _query_doh("cloudflare", domain)
        ips_b = _query_doh("google", domain)

        if system_ips is None and ips_a is None and ips_b is None:
            status = "unreachable"
            message = f"No DNS method could resolve '{domain}'."
        elif not system_ips or not ips_a or not ips_b:
            status = "inconclusive"
            message = f"Not all DNS/DoH sources answered for '{domain}'."
        else:
            references_agree = bool(set(ips_a) & set(ips_b))
            system_matches_reference = bool(set(system_ips) & (set(ips_a) | set(ips_b)))
            if references_agree and not system_matches_reference:
                suspicious_count += 1
                status = "suspicious"
                message = (
                    f"Configured DNS returned different addresses for '{domain}' "
                    "while DNS-over-HTTPS references agreed."
                )
            elif not references_agree:
                status = "inconclusive"
                message = (
                    f"DoH references returned different CDN addresses for '{domain}'; "
                    "no security conclusion can be made."
                )
            else:
                status = "consistent"
                message = f"Configured DNS is consistent with DoH reference results for '{domain}'."

        findings.append({
            "domain": domain,
            "status": status,
            "system_ips": system_ips,
            "ips_a": ips_a,
            "ips_b": ips_b,
            "reference_a": "Cloudflare DoH",
            "reference_b": "Google DoH",
            "message": message,
        })

    if suspicious_count >= 2:
        overall = "suspicious"
    elif all(item["status"] == "unreachable" for item in findings):
        overall = "unreachable"
    elif any(item["status"] in {"suspicious", "inconclusive"} for item in findings):
        overall = "inconclusive"
    else:
        overall = "consistent"
    return {"status": overall, "details": findings}

"""
Discovery engine for ARGUS.

Provides two modes:

1. Real checks — DNS-over-HTTPS lookups, HTTP header analysis and TLS
   certificate inspection built on the Python standard library. These run
   against hosts the operator explicitly authorises.

2. Lab mode — a deterministic, self-contained inventory for the demo domain
   (``acme-lab.local``). It produces realistic assets and findings and evolves
   between scans (a "new" subdomain appears on later scans) so change
   detection and the dashboard can be demonstrated without scanning anything
   real. Only use this on domains you own or are authorised to assess.
"""

from __future__ import annotations

import json
import random
import socket
import ssl
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

LAB_DOMAIN = "acme-lab.local"

# ── Real network checks (stdlib only) ────────────────────────────────────────

_DOH_URLS = [
    "https://cloudflare-dns.com/dns-query?name={q}&type=A",
    "https://dns.google/resolve?name={q}&type=A",
]


def query_dns_a(hostname: str, timeout: float = 4.0) -> List[str]:
    """Resolve A records via DNS-over-HTTPS, falling back to getaddrinfo."""
    results: List[str] = []
    for url_tpl in _DOH_URLS:
        try:
            req = urllib.request.Request(
                url_tpl.format(q=hostname),
                headers={"Accept": "application/dns-json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
            answers = data.get("Answer", [])
            for a in answers:
                if a.get("type") == 1:  # A
                    results.append(a["data"])
            if results:
                return results
        except Exception:
            continue
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            results.append(info[4][0])
    except Exception:
        pass
    return list(dict.fromkeys(results))


def check_http(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Fetch an HTTPS response and return status + security-relevant headers."""
    url = f"https://{hostname}:{port}/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "ARGUS-Scan/0.1"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
        return {"ok": True, "status": status, "headers": headers}
    except urllib.error.HTTPError as e:
        return {"ok": True, "status": e.code, "headers": {k.lower(): v for k, v in e.headers.items()}}
    except Exception as e:
        return {"ok": False, "error": str(e), "status": None, "headers": {}}


def check_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Inspect the TLS certificate and return its notAfter (expiry)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
        not_after = cert.get("notAfter", "")
        return {"ok": True, "not_after": not_after}
    except Exception as e:
        return {"ok": False, "error": str(e), "not_after": None}


def discover_subdomains(domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
    """Enumerate subdomains using a small wordlist over DoH."""
    base = wordlist or [
        "www", "mail", "vpn", "api", "portal", "admin", "dev", "staging", "test",
        "files", "git", "docs", "status", "blog", "shop", "billing", "webmail",
        "ftp", "remote", "internal", "db", "backup", "jenkins", "grafana",
        "kibana", "monitor", "old", "legacy",
    ]
    found = [domain]  # apex
    for sub in base:
        host = f"{sub}.{domain}"
        try:
            if query_dns_a(host):
                found.append(host)
        except Exception:
            continue
    return found


# ── Lab generator (deterministic, evolves across scans) ──────────────────────

_SUBDOMAIN_POOL = [
    "www", "mail", "vpn", "api", "portal", "admin", "dev", "staging", "test",
    "files", "git", "docs", "status", "blog", "shop", "billing", "webmail",
    "ftp", "remote", "internal", "db", "backup", "jenkins", "grafana",
    "kibana", "monitor", "old", "legacy", "edge", "cdn", "assets", "pay",
    "auth", "ws", "mq", "logs", "metrics", "cache", "search", "analytics",
]

# Introduced only on later scans (change detection demo)
_LATE_SUBDOMAINS = ["new-portal", "unsecured-admin", "temp-export"]


def _lab_asset(hostname: str, index: int, now: datetime, rng: random.Random) -> Dict[str, Any]:
    is_web = rng.random() < 0.72
    asset = {
        "hostname": hostname,
        "asset_type": "Subdomain",
        "ip": rng.choice(["10.20.1.1", "10.20.1.2", "10.20.1.3", "10.20.2.10", "10.20.3.4", "172.16.5.7"]),
        "status": "Online" if rng.random() < 0.92 else "Offline",
        "is_web": is_web,
        "http_status": None,
        "open_ports": [],
        "tls_expiry": None,
        "security_headers": {},
        "is_new": False,
    }
    if is_web:
        asset["http_status"] = rng.choice([200, 200, 200, 200, 301, 302, 403, 500])
        asset["security_headers"] = {
            "strict-transport-security": rng.random() < 0.5,
            "content-security-policy": rng.random() < 0.25,
            "x-content-type-options": rng.random() < 0.6,
            "x-frame-options": rng.random() < 0.55,
        }
        asset["open_ports"] = rng.choice([[80, 443], [443], [80, 443, 8080], [443, 8443]])
        if rng.random() < 0.5:
            asset["tls_expiry"] = (now + timedelta(days=rng.choice([-12, 3, 18, 60, 120, 200, 350]))).isoformat()
    else:
        asset["open_ports"] = rng.choice([[22], [21], [22, 3306], [3389], [25, 110], [9090]])
    return asset


def generate_lab_inventory(domain: str, scan_index: int = 0) -> List[Dict[str, Any]]:
    """Return the deterministic asset inventory for *scan_index*-th scan."""
    rng = random.Random(f"{domain}:{scan_index}")
    now = datetime.now(timezone.utc)
    assets: List[Dict[str, Any]] = [{"hostname": domain, "asset_type": "Apex", "ip": "10.20.1.1",
                                     "status": "Online", "is_web": True, "http_status": 200,
                                     "open_ports": [80, 443], "tls_expiry": (now + timedelta(days=120)).isoformat(),
                                     "security_headers": {"strict-transport-security": True}, "is_new": False}]
    pool = list(_SUBDOMAIN_POOL)
    rng.shuffle(pool)
    count = 40
    chosen = pool[:count]
    # Later scans introduce new subdomains (change detection)
    for i, late in enumerate(_LATE_SUBDOMAINS):
        if scan_index > i:
            chosen.append(late)
    for sub in chosen:
        assets.append(_lab_asset(f"{sub}.{domain}", len(assets), now, rng))
    return assets


def findings_for_asset(asset: Dict[str, Any], now: datetime, rng: random.Random) -> List[Dict[str, Any]]:
    """Compute deterministic findings for a single lab asset."""
    findings: List[Dict[str, Any]] = []
    host = asset["hostname"]
    is_web = asset["is_web"]

    # TLS expiry
    if asset.get("tls_expiry"):
        expiry = datetime.fromisoformat(asset["tls_expiry"])
        days = (expiry - now).days
        if days < 0:
            findings.append({
                "category": "TLS", "title": "Expired TLS certificate",
                "detail": f"Certificate for {host} expired {abs(days)} days ago.",
                "severity": "Critical" if days < -7 else "High",
                "exposure": "Internet", "confidence": 0.95,
                "recommendation": "Renew and replace the certificate immediately.",
            })
        elif days <= 30:
            findings.append({
                "category": "TLS", "title": "TLS certificate expires soon",
                "detail": f"Certificate for {host} expires in {days} day(s).",
                "severity": "Medium", "exposure": "Internet", "confidence": 0.9,
                "recommendation": "Renew the certificate before expiry.",
            })

    if is_web:
        headers = asset.get("security_headers", {})
        if headers.get("content-security-policy") is False:
            findings.append({
                "category": "Headers", "title": "Missing Content-Security-Policy header",
                "detail": f"{host} does not return a Content-Security-Policy header.",
                "severity": "Low", "exposure": "Internet", "confidence": 0.8,
                "recommendation": "Implement an appropriate CSP policy.",
            })
        if headers.get("strict-transport-security") is False:
            findings.append({
                "category": "Headers", "title": "Missing HSTS header",
                "detail": f"{host} does not return Strict-Transport-Security.",
                "severity": "Low", "exposure": "Internet", "confidence": 0.8,
                "recommendation": "Enable HSTS with a sensible max-age.",
            })

    # Sensitive subdomain heuristics
    sub = host.split(".")[0].lower() if "." in host else host
    if sub in ("admin", "portal", "jenkins", "grafana", "kibana", "unsecured-admin", "new-portal"):
        findings.append({
            "category": "Exposure", "title": "Administrative portal exposed",
            "detail": f"An administrative interface ({host}) is reachable from the internet.",
            "severity": "High", "exposure": "Internet", "confidence": 0.85,
            "recommendation": "Verify ownership; restrict access or move behind VPN.",
        })
    if sub in ("db", "ftp", "remote", "temp-export", "internal"):
        findings.append({
            "category": "Exposure", "title": "Unexpected service exposed to the internet",
            "detail": f"{host} exposes a service ({','.join(str(p) for p in asset.get('open_ports', []))}) that should not be internet-facing.",
            "severity": "High", "exposure": "Internet", "confidence": 0.8,
            "recommendation": "Validate exposure and apply access controls.",
        })
    if sub in ("old", "legacy", "test", "dev", "staging"):
        findings.append({
            "category": "Lifecycle", "title": "Legacy / dev asset exposed",
            "detail": f"{host} looks like a legacy or development asset reachable externally.",
            "severity": "Medium", "exposure": "Internet", "confidence": 0.7,
            "recommendation": "Decommission or restrict access to this asset.",
        })

    # Port-based
    ports = asset.get("open_ports", [])
    if 3389 in ports:
        findings.append({
            "category": "Exposure", "title": "RDP exposed to the internet",
            "detail": f"{host} has RDP (3389) exposed.",
            "severity": "High", "exposure": "Internet", "confidence": 0.9,
            "recommendation": "Restrict RDP access; use a VPN or jump host.",
        })
    if 3306 in ports:
        findings.append({
            "category": "Exposure", "title": "MySQL port exposed",
            "detail": f"{host} exposes MySQL (3306).",
            "severity": "Critical", "exposure": "Internet", "confidence": 0.85,
            "recommendation": "Remove public access to the database.",
        })
    return findings


def generate_lab_findings(asset: Dict[str, Any], scan_index: int = 0) -> List[Dict[str, Any]]:
    rng = random.Random(f"f:{asset['hostname']}:{scan_index}")
    return findings_for_asset(asset, datetime.now(timezone.utc), rng)


def scan_lab(domain: str, scan_index: int = 0) -> Dict[str, Any]:
    """Produce the full lab result for a scan: assets plus computed findings."""
    assets = generate_lab_inventory(domain, scan_index)
    new_assets = [a for a in assets if "new" in a["hostname"].split(".")[0] or a["hostname"] in
                  [f"{s}.{domain}" for s in _LATE_SUBDOMAINS]]
    return {
        "domain": domain,
        "scan_index": scan_index,
        "assets": assets,
        "new_assets": new_assets,
        "findings": [],
    }

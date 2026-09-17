# language: Python, file: Program/web/triage.py, target: Red Sky web — triage
# Fingerprint stack (server, language, framework, CMS, JS libs) from headers,
# cookies, HTML, favicon hash. Reports every signal. No exploitation.

import hashlib
import json
import re
import socket
import ssl
import sys
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# fingerprints — substring in header/body → tech name
HEADER_FP = {
    "server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "openresty": "OpenResty",
        "litespeed": "LiteSpeed",
        "caddy": "Caddy",
        "gunicorn": "Gunicorn",
        "uvicorn": "Uvicorn",
        "werkzeug": "Werkzeug",
        "kestrel": "Kestrel",
        "tomcat": "Apache Tomcat",
        "jetty": "Jetty",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express",
        "next.js": "Next.js",
        "nuxt": "Nuxt",
    },
}

COOKIE_FP = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java/Tomcat",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "django": "Django",
    "_rails": "Ruby on Rails",
    "csrftoken": "Django",
    "connect.sid": "Express/Node",
    "next-auth": "Next.js",
}

BODY_FP = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "/sites/default/files/": "Drupal",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "shopify": "Shopify",
    "magento": "Magento",
    "woocommerce": "WooCommerce",
    "react": "React",
    "vue.js": "Vue.js",
    "angular": "Angular",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "tailwind": "Tailwind",
    "__next_data__": "Next.js",
    "nuxt": "Nuxt",
    "csrf-token": "Rails",
    "laravel": "Laravel",
    "stripe": "Stripe",
    "recaptcha": "Google reCAPTCHA",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
}


def _favicon_hash(url: str) -> Optional[str]:
    """Shodan-style favicon hash — mmh3 (MurmurHash3) of the base64 favicon."""
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent": UA})
        if r.status_code != 200:
            return None
        import base64
        try:
            import mmh3
            b64 = base64.encodebytes(r.content)
            return str(mmh3.hash(b64))
        except ImportError:
            # fallback: sha256
            return hashlib.sha256(r.content).hexdigest()[:16]
    except requests.RequestException:
        return None


def _tls_info(url: str) -> Dict:
    """TLS cert details."""
    u = urlparse(url)
    if u.scheme != "https":
        return {}
    host = u.hostname
    port = u.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                if not cert:
                    return {}
                subj = dict(x[0] for x in cert.get("subject", []))
                iss = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "subject_cn": subj.get("commonName", ""),
                    "subject_org": subj.get("organizationName", ""),
                    "issuer_cn": iss.get("commonName", ""),
                    "issuer_org": iss.get("organizationName", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "san": cert.get("subjectAltName", []),
                }
    except (ssl.SSLError, socket.error, OSError):
        return {}


def _match_fp(response, body: str) -> List[str]:
    hits = set()
    for header, table in HEADER_FP.items():
        val = response.headers.get(header, "").lower()
        if val:
            for key, name in table.items():
                if key in val:
                    hits.add(f"{name} ({val[:40]})")

    for cookie_name in response.cookies.keys():
        for key, name in COOKIE_FP.items():
            if key.lower() in cookie_name.lower():
                hits.add(name)

    low = body.lower()
    for key, name in BODY_FP.items():
        if key.lower() in low:
            hits.add(name)

    return sorted(hits)


def _parse_headers(headers) -> Dict[str, str]:
    """Pick the interesting headers."""
    keep = [
        "server", "x-powered-by", "content-type", "x-frame-options",
        "content-security-policy", "strict-transport-security",
        "x-content-type-options", "referrer-policy", "permissions-policy",
        "set-cookie", "x-generator", "via", "x-cache", "cf-ray",
        "x-aspnet-version", "x-aspnetmvc-version", "x-drupal-cache",
    ]
    out = {}
    for k in keep:
        v = headers.get(k)
        if v:
            out[k] = v[:200]
    return out


def _security_headers(headers) -> Dict[str, str]:
    """Best-practice checks. Empty value = missing."""
    checks = {
        "Strict-Transport-Security": headers.get("strict-transport-security", ""),
        "Content-Security-Policy":   headers.get("content-security-policy", ""),
        "X-Frame-Options":           headers.get("x-frame-options", ""),
        "X-Content-Type-Options":    headers.get("x-content-type-options", ""),
        "Referrer-Policy":           headers.get("referrer-policy", ""),
        "Permissions-Policy":        headers.get("permissions-policy", ""),
    }
    return checks


def cmd_triage(url: str) -> int:
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    base = f"{u.scheme}://{u.netloc}"

    print_info(f"triaging {url}")
    print()

    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": UA},
                        verify=False, allow_redirects=True)
    except requests.RequestException as e:
        print_err(f"request failed: {e}")
        return 1

    body = r.text[:500_000]  # cap for matching

    print_kv("status", r.status_code)
    print_kv("final_url", r.url)
    print_kv("content-type", r.headers.get("content-type", "?"))
    print_kv("content-length", r.headers.get("content-length", "?"))

    # headers
    print()
    print(f"{ARTERY}{BOLD}  headers{RESET}")
    for k, v in _parse_headers(r.headers).items():
        print(f"  {ARTERY}▓{RESET} {BONE}{k:<30}{RESET} {ASH}{v}{RESET}")

    # fingerprints
    fps = _match_fp(r, body)
    print()
    print(f"{ARTERY}{BOLD}  fingerprints{RESET}")
    if fps:
        for f in fps:
            print(f"  {ARTERY}▓{RESET} {BONE}{f}{RESET}")
    else:
        print(f"  {CLOT}(none matched){RESET}")

    # favicon
    fav_url = f"{base}/favicon.ico"
    fav_hash = _favicon_hash(fav_url)
    if fav_hash:
        print()
        print(f"{ARTERY}{BOLD}  favicon{RESET}")
        print(f"  {ARTERY}▓{RESET} hash: {BONE}{fav_hash}{RESET}")
        print(f"  {ASH}  search on shodan: http-hash:{fav_hash}{RESET}")

    # TLS
    tls = _tls_info(url)
    if tls:
        print()
        print(f"{ARTERY}{BOLD}  tls{RESET}")
        print_kv("subject", tls.get("subject_cn", ""))
        print_kv("issuer", tls.get("issuer_org", tls.get("issuer_cn", "")))
        print_kv("expires", tls.get("not_after", ""))
        sans = tls.get("san", [])
        if sans:
            print(f"  {ARTERY}▓{RESET} SANs: {', '.join(s[1] for s in sans[:6])}")

    # security headers
    print()
    print(f"{ARTERY}{BOLD}  security headers{RESET}")
    for name, val in _security_headers(r.headers).items():
        if val:
            print(f"  {OK}▓{RESET} {BONE}{name:<30}{RESET} {ASH}present{RESET}")
        else:
            print(f"  {SCARLET}░{RESET} {BONE}{name:<30}{RESET} {CLOT}missing{RESET}")

    # output
    result = {
        "url": r.url,
        "status": r.status_code,
        "headers": dict(r.headers),
        "fingerprints": fps,
        "favicon_hash": fav_hash,
        "tls": tls,
        "security_headers": _security_headers(r.headers),
    }
    out = OUTPUT_DIR / f"triage_{u.netloc.replace(':', '_')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky web triage <url>")
        return 2
    return cmd_triage(args[0])


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

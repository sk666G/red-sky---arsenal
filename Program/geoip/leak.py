# language: Python, file: Program/geoip/leak.py, target: Red Sky geoip — app-region leak
# Tries to work out the target's approximate region through the CDN edge
# they hit for a given service. Discord, Telegram, Instagram, TikTok etc.
# Not a precise IP — a coarse city/region signal derived from latency and
# edge node IDs. Use as a cross-check on lookup() results.

import socket
import ssl
import time
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from .lookup import lookup


APPS = {
    "discord":   ["discord.com", "cdn.discordapp.com", "gateway.discord.gg"],
    "telegram":  ["telegram.org", "web.telegram.org", "t.me"],
    "instagram": ["instagram.com", "scontent.cdninstagram.com"],
    "facebook":  ["facebook.com", "graph.facebook.com"],
    "tiktok":    ["tiktok.com", "www.tiktok.com"],
    "whatsapp":  ["web.whatsapp.com", "static.whatsapp.net"],
    "twitter":   ["twitter.com", "abs.twimg.com"],
    "youtube":   ["youtube.com", "googlevideo.com"],
    "netflix":   ["netflix.com", "nflxvideo.net"],
}


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _tls_latency(host, port=443, timeout=5):
    """Time a TLS handshake. Faster = edge node is closer."""
    try:
        t0 = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.do_handshake()
                dt = time.time() - t0
        return dt
    except (socket.timeout, ssl.SSLError, OSError):
        return None


def _cloudflare_edge(host):
    """Ask a Cloudflare-fronted host which edge node answered."""
    try:
        import requests
        r = requests.get(f"https://{host}/cdn-cgi/trace", timeout=8,
                         headers={"User-Agent": "Mozilla/5.0"})
        for line in r.text.splitlines():
            if line.startswith("colo="):
                return line.split("=", 1)[1]
    except Exception:
        pass
    return None


def probe_app(app: str) -> List[Dict]:
    hosts = APPS.get(app, [])
    results = []
    for host in hosts:
        ip = _resolve(host)
        if not ip:
            continue
        lat = _tls_latency(host)
        edge = None
        if "discord" in host or "cloudflare" in host:
            edge = _cloudflare_edge(host)
        geo = lookup(ip) if ip else None
        results.append({
            "host": host,
            "ip": ip,
            "latency_ms": int(lat * 1000) if lat else None,
            "cloudflare_edge": edge,
            "ip_geo": geo,
        })
    return results


def cmd_probe(app: str) -> int:
    if app == "all":
        apps = list(APPS.keys())
    elif app in APPS:
        apps = [app]
    else:
        print_err(f"unknown app: {app}")
        print_info("available: " + ", ".join(APPS.keys()) + ", all")
        return 2

    print_info(f"probing {len(apps)} app(s) for edge and region signals")
    print()

    for a in apps:
        print(f"{ARTERY}{BOLD}── {a}{RESET}")
        results = probe_app(a)
        if not results:
            print(f"  {CLOT}no resolution{RESET}")
            print()
            continue
        for r in results:
            lat = r["latency_ms"]
            lat_str = f"{lat}ms" if lat is not None else "?"
            edge = r.get("cloudflare_edge") or ""
            geo = r.get("ip_geo") or {}
            loc = ", ".join(filter(None, [geo.get("city"), geo.get("country")]))
            print(f"  {ARTERY}*{RESET} {BONE}{r['host']:<30}{RESET} {ASH}{r['ip']:<16}{RESET} "
                  f"{lat_str:>8}  {SCARLET}{edge:<5}{RESET}  {ASH}{loc}{RESET}")
        print()
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky geoip leak <app|all>")
        return 2
    return cmd_probe(args[0].lower())


if __name__ == "__main__":
    import sys
    sys.exit(run_cli(sys.argv[1:]))

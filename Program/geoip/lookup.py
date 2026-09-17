# language: Python, file: Program/geoip/lookup.py, target: Red Sky geoip — multi-source geolocation
# Tries multiple free providers in order, caches results to Data/geoip_cache.json.

import ipaddress
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import DATA_DIR


CACHE_FILE = DATA_DIR / "geoip_cache.json"
CACHE_TTL = 86400 * 7

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
    except ValueError:
        return True


def _load_cache() -> Dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: Dict):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        CACHE_FILE.write_text(json.dumps(cache))
    except OSError:
        pass


def _ipapi(ip: str, timeout: int = 8) -> Optional[Dict]:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            headers={"User-Agent": UA}, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("status") != "success":
            return None
        return {
            "source": "ip-api.com",
            "ip": d.get("query", ip),
            "country": d.get("country", ""),
            "country_code": d.get("countryCode", ""),
            "region": d.get("regionName", ""),
            "city": d.get("city", ""),
            "zip": d.get("zip", ""),
            "lat": d.get("lat"),
            "lon": d.get("lon"),
            "timezone": d.get("timezone", ""),
            "isp": d.get("isp", ""),
            "org": d.get("org", ""),
            "asn": d.get("as", ""),
        }
    except (requests.RequestException, ValueError):
        return None


def _ipinfo(ip: str, timeout: int = 8) -> Optional[Dict]:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json",
                         headers={"User-Agent": UA}, timeout=timeout)
        if r.status_code != 200:
            return None
        d = r.json()
        loc = (d.get("loc") or ",").split(",")
        lat = None
        lon = None
        if loc and loc[0]:
            try:
                lat = float(loc[0])
            except ValueError:
                pass
        if len(loc) > 1 and loc[1]:
            try:
                lon = float(loc[1])
            except ValueError:
                pass
        return {
            "source": "ipinfo.io",
            "ip": d.get("ip", ip),
            "country": d.get("country", ""),
            "country_code": d.get("country", ""),
            "region": d.get("region", ""),
            "city": d.get("city", ""),
            "zip": d.get("postal", ""),
            "lat": lat,
            "lon": lon,
            "timezone": d.get("timezone", ""),
            "isp": d.get("org", ""),
            "org": d.get("org", ""),
            "asn": d.get("org", ""),
        }
    except (requests.RequestException, ValueError):
        return None


def _geojsonlite(ip: str, timeout: int = 8) -> Optional[Dict]:
    try:
        r = requests.get(f"https://geo.jsonlite.dev/json/{ip}.html",
                         headers={"User-Agent": UA}, timeout=timeout)
        if r.status_code != 200:
            return None
        d = r.json()
        return {
            "source": "geo.jsonlite.dev",
            "ip": ip,
            "country": d.get("country_name", d.get("country", "")),
            "country_code": d.get("country_code", ""),
            "region": d.get("region", ""),
            "city": d.get("city", ""),
            "zip": d.get("postal", ""),
            "lat": d.get("latitude"),
            "lon": d.get("longitude"),
            "timezone": d.get("timezone", ""),
            "isp": d.get("registered_country", ""),
            "org": "",
            "asn": "",
        }
    except (requests.RequestException, ValueError):
        return None


PROVIDERS = [_ipapi, _ipinfo, _geojsonlite]


def lookup(ip: str, timeout: int = 8) -> Optional[Dict]:
    """Return geo dict for ip from the first provider that responds. Cached 7 days."""
    if _is_private(ip):
        return {"source": "local", "ip": ip, "country": "private", "private": True}

    cache = _load_cache()
    entry = cache.get(ip)
    if entry and (time.time() - entry.get("_ts", 0)) < CACHE_TTL:
        return entry.get("data")

    for provider in PROVIDERS:
        result = provider(ip, timeout)
        if result:
            cache[ip] = {"_ts": time.time(), "data": result}
            _save_cache(cache)
            return result
    return None


def lookup_multi(ip: str, timeout: int = 8) -> List[Dict]:
    """Return results from every provider that responds."""
    if _is_private(ip):
        return [{"source": "local", "ip": ip, "country": "private", "private": True}]
    out = []
    for provider in PROVIDERS:
        r = provider(ip, timeout)
        if r:
            out.append(r)
    return out


def cmd_lookup(ip: str, all_sources: bool = False) -> int:
    if all_sources:
        results = lookup_multi(ip)
    else:
        r = lookup(ip)
        results = [r] if r else []

    if not results:
        print_err(f"no geo data for {ip}")
        return 1

    for r in results:
        print()
        print(f"  {ARTERY}{BOLD}▓{RESET} {BONE}{r.get('source', '?')}{RESET}")
        for k, v in (
            ("ip", r.get("ip")),
            ("country", r.get("country")),
            ("country_code", r.get("country_code")),
            ("region", r.get("region")),
            ("city", r.get("city")),
            ("zip", r.get("zip")),
            ("lat", r.get("lat")),
            ("lon", r.get("lon")),
            ("timezone", r.get("timezone")),
            ("isp", r.get("isp")),
            ("org", r.get("org")),
            ("asn", r.get("asn")),
        ):
            if v:
                print_kv(k, v)
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky geoip lookup <ip> [--all]")
        return 2
    ip = args[0]
    all_sources = "--all" in args
    return cmd_lookup(ip, all_sources)


if __name__ == "__main__":
    import sys
    sys.exit(run_cli(sys.argv[1:]))

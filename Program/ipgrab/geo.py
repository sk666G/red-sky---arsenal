# language: Python, file: Program/ipgrab/geo.py, target: Red Sky ipgrab — geo lookup
# Multi-source IP geolocation. Tries providers in order, caches results.

import ipaddress
import json
import time
from pathlib import Path
from typing import Dict, Optional

import requests

from Program.utils.paths import DATA_DIR


CACHE_FILE = DATA_DIR / "geoip_cache.json"
CACHE_TTL = 86400 * 7  # 7 days

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


def _ip_api(ip: str) -> Optional[Dict]:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            headers={"User-Agent": UA}, timeout=8,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("status") != "success":
            return None
        return {
            "source": "ip-api.com",
            "ip": data.get("query", ip),
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "zip": data.get("zip", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
        }
    except (requests.RequestException, ValueError):
        return None


def _ipinfo(ip: str) -> Optional[Dict]:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers={"User-Agent": UA}, timeout=8)
        if r.status_code != 200:
            return None
        d = r.json()
        loc = d.get("loc", ",").split(",") if d.get("loc") else ["", ""]
        return {
            "source": "ipinfo.io",
            "ip": d.get("ip", ip),
            "country": d.get("country", ""),
            "region": d.get("region", ""),
            "city": d.get("city", ""),
            "zip": d.get("postal", ""),
            "lat": float(loc[0]) if loc[0] else None,
            "lon": float(loc[1]) if len(loc) > 1 and loc[1] else None,
            "timezone": d.get("timezone", ""),
            "isp": d.get("org", ""),
            "org": d.get("org", ""),
            "asn": d.get("org", ""),
        }
    except (requests.RequestException, ValueError):
        return None


def lookup(ip: str) -> Optional[Dict]:
    """Return geo dict for ip, or None if private/unresolvable. Cached 7 days."""
    if _is_private(ip):
        return {"source": "local", "ip": ip, "country": "private", "private": True}

    cache = _load_cache()
    entry = cache.get(ip)
    if entry and (time.time() - entry.get("_ts", 0)) < CACHE_TTL:
        return entry.get("data")

    for provider in (_ip_api, _ipinfo):
        result = provider(ip)
        if result:
            cache[ip] = {"_ts": time.time(), "data": result}
            _save_cache(cache)
            return result

    return None

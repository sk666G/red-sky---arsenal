# language: Python, file: Program/cctv/discover.py, target: Red Sky cctv — discover
# CIDR sweep across RTSP (554) + HTTP admin ports + ONVIF (80, 8899).
# Vendor fingerprint from WWW-Authenticate realm and Server header.

import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


RTSP_PORT = 554
HTTP_PORTS = [80, 8000, 8080, 8081, 8899, 8888, 443, 8443]
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

VENDOR_HINTS = {
    "hikvision":  ["hikvision", "dvrdvs", "webs"],
    "dahua":      ["dahua", "webs", "dvrdvs", "general_"],
    "axis":       ["axis", "AXIS"],
    "reolink":    ["reolink"],
    "foscam":     ["foscam", "ipcam"],
    "vivotek":    ["vivotek", "network camera"],
    "amcrest":    ["amcrest", "dahua"],
    "uniview":    ["uniview", "unv"],
    "bosch":      ["bosch"],
    "samsung":    ["samsung", "techwin"],
    "panasonic":  ["panasonic", "i-PRO"],
    "geovision":  ["geovision"],
    "dlink":      ["d-link", "dlink"],
    "tp-link":    ["tp-link", "tapo"],
    "swann":      ["swann"],
    "lorex":      ["lorex"],
}


def _vendor_from_banner(banner: str) -> str:
    b = banner.lower()
    for vendor, hints in VENDOR_HINTS.items():
        for h in hints:
            if h.lower() in b:
                return vendor
    return "unknown"


def _expand(target: str) -> List[str]:
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            return []
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        try:
            return [socket.gethostbyname(target)]
        except socket.gaierror:
            return []


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def _rtsp_probe(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Send RTSP OPTIONS, read Server header."""
    try:
        s = socket.create_connection((ip, RTSP_PORT), timeout=timeout)
        s.settimeout(timeout)
        req = (f"OPTIONS rtsp://{ip}:{RTSP_PORT}/ RTSP/1.0\r\n"
               f"CSeq: 1\r\n"
               f"User-Agent: {UA}\r\n\r\n").encode()
        s.sendall(req)
        data = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        for line in data.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
        return data.splitlines()[0] if data else "rtsp"
    except (socket.timeout, OSError):
        return None


def _http_probe(ip: str, port: int, timeout: float = 3.0) -> Optional[Dict]:
    """Hit the port, look at Server header + WWW-Authenticate realm."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": UA},
                         verify=False, allow_redirects=False)
    except requests.RequestException:
        return None

    banner = f"{r.headers.get('Server','')} {r.headers.get('WWW-Authenticate','')} {r.text[:200]}"
    vendor = _vendor_from_banner(banner)

    return {
        "port": port,
        "scheme": scheme,
        "status": r.status_code,
        "server": r.headers.get("Server", ""),
        "www_authenticate": r.headers.get("WWW-Authenticate", ""),
        "realm": _realm(r.headers.get("WWW-Authenticate", "")),
        "title": _title(r.text),
        "vendor": vendor,
    }


def _realm(hdr: str) -> str:
    if "realm=" not in hdr:
        return ""
    try:
        return hdr.split("realm=", 1)[1].split('"')[1]
    except IndexError:
        return ""


def _title(html: str) -> str:
    try:
        if "<title>" in html.lower():
            start = html.lower().index("<title>") + 7
            end = html.lower().index("</title>", start)
            return html[start:end].strip()[:80]
    except (ValueError, IndexError):
        pass
    return ""


def _check_host(ip: str, timeout: float) -> Optional[Dict]:
    rtsp = _rtsp_probe(ip, timeout) if _tcp_open(ip, RTSP_PORT, timeout) else None

    http_hits = []
    for port in HTTP_PORTS:
        if _tcp_open(ip, port, timeout):
            hit = _http_probe(ip, port, timeout + 1)
            if hit:
                http_hits.append(hit)

    if not rtsp and not http_hits:
        return None

    vendor = "unknown"
    if rtsp:
        vendor = _vendor_from_banner(rtsp)
    if vendor == "unknown":
        for h in http_hits:
            if h["vendor"] != "unknown":
                vendor = h["vendor"]
                break

    return {"ip": ip, "vendor": vendor, "rtsp": rtsp, "http": http_hits}


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky cctv discover <cidr|ip> [threads]")
        return 2

    target = args[0]
    threads = int(args[1]) if len(args) > 1 else 128
    timeout = 1.5

    hosts = _expand(target)
    if not hosts:
        print_err(f"cannot expand {target}")
        return 1

    print_info(f"CCTV discover on {target} ({len(hosts)} hosts, {threads} threads)")
    print_info(f"probing rtsp/554 and http ports {HTTP_PORTS}")
    print()

    hits: List[Dict] = []
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_check_host, h, timeout): h for h in hosts}
        for f in as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
                rtsp_mark = f"{OK}rtsp{RESET}" if r["rtsp"] else f"{CLOT}----{RESET}"
                http_count = len(r["http"])
                http_mark = f"{OK}{http_count}x http{RESET}" if http_count else f"{CLOT}--------{RESET}"
                print(f"  {ARTERY}▓{RESET} {BONE}{r['ip']:<16}{RESET} "
                      f"{SCARLET}{r['vendor']:<12}{RESET} {rtsp_mark}  {http_mark}")
                for h in r["http"]:
                    extra = h["server"] or h["title"] or h["realm"]
                    if extra:
                        print(f"     {ASH}{h['scheme']}://{h['ip']}:{h['port']}{RESET}  {CLOT}{extra[:60]}{RESET}")

    dt = time.time() - t0
    print()
    print_kv("found", len(hits))
    print_kv("elapsed", f"{dt:.1f}s")

    out = OUTPUT_DIR / f"cctv_discover_{target.replace('/', '_').replace('.', '-')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

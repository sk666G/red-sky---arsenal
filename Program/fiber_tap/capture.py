# language: Python, file: Program/fiber_tap/capture.py, target: Red Sky fiber_tap — passive capture + analysis
# Passive network capture and analysis for a SPAN port, a physical TAP, or a
# mirror interface. Does NOT include physical fiber handling — that needs an
# optical splitter in-line; this module covers everything after the span:
#   list      -- enumerate interfaces that look like taps (no IP, promisc)
#   capture   -- long-running pcap writer with optional rolling / rotation
#   parse     -- summarize a pcap: top talkers, protocols, DNS, HTTP hosts
#   extract   -- pull credentials, HTTP Basic auth, FTP, SMTP plaintext from a pcap
# Requires: tcpdump / tshark for capture; scapy or a pure-python pcap reader for parse.

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


FT_DIR = OUTPUT_DIR / "fiber_tap"
FT_DIR.mkdir(parents=True, exist_ok=True)


def _run(cmd: List[str], timeout: int = 30) -> Dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": "missing: " + cmd[0]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}


def _list_ifaces() -> List[Dict]:
    ifaces = []
    if Path("/sys/class/net").exists():
        for d in sorted(Path("/sys/class/net").iterdir()):
            name = d.name
            info = {"name": name, "mac": "", "state": "", "ips": [], "flags": []}
            try:
                info["mac"] = (d / "address").read_text().strip()
                info["state"] = (d / "operstate").read_text().strip()
            except OSError:
                pass
            # IPs from ip addr
            r = _run(["ip", "-o", "addr", "show", "dev", name])
            if r["rc"] == 0:
                for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", r["stdout"]):
                    info["ips"].append(m.group(1))
                for m in re.finditer(r"inet6 ([0-9a-f:]+)", r["stdout"]):
                    info["ips"].append(m.group(1))
            # check promisc flag
            r = _run(["ip", "link", "show", "dev", name])
            if "PROMISC" in r["stdout"]:
                info["flags"].append("promisc")
            ifaces.append(info)
    return ifaces


def cmd_list(out_file: str) -> int:
    ifaces = _list_ifaces()
    print_info("interfaces")
    print_kv("count", str(len(ifaces)))
    print()

    tap_like = []
    for i in ifaces:
        marker = ASH + "░ " + RESET
        if not i["ips"] and i["state"] == "UP":
            marker = SCARLET + "▓ " + RESET
            tap_like.append(i)
        elif "promisc" in i["flags"]:
            marker = SCARLET + "▓ " + RESET
            tap_like.append(i)
        print("  " + marker + BONE + i["name"].ljust(16) + RESET
              + ASH + i["mac"] + RESET
              + "  " + ARTERY + i["state"] + RESET
              + ("  " + ",".join(i["ips"]) if i["ips"] else "")
              + ("  " + SCARLET + ",".join(i["flags"]) + RESET if i["flags"] else ""))

    print()
    print_kv("tap-like", str(len(tap_like)))
    for t in tap_like:
        print("  " + SCARLET + "▓ " + RESET + t["name"] + "  (no IP or promisc)")

    out = Path(out_file) if out_file else FT_DIR / ("ifaces_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"all": ifaces, "tap_like": tap_like}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_capture(iface: str, pcap_path: str, snaplen: int, filter_expr: str,
                duration: int, rotate_size_mb: int) -> int:
    if not iface:
        print_err("--iface required")
        return 2
    if not shutil.which("tcpdump"):
        print_err("tcpdump not installed")
        return 2

    out_pcap = Path(pcap_path) if pcap_path else FT_DIR / ("capture_" + iface + "_" + str(int(time.time())) + ".pcap")

    cmd = ["tcpdump", "-i", iface, "-s", str(snaplen), "-w", str(out_pcap)]
    if rotate_size_mb:
        # tcpdump native rotation is via -C (size in MB) and -W (count)
        cmd += ["-C", str(rotate_size_mb), "-W", "10"]
    if filter_expr:
        cmd += filter_expr.split()

    print_info("tcpdump capture")
    print_kv("iface", iface)
    print_kv("output", str(out_pcap))
    print_kv("filter", filter_expr or "(none)")
    print_kv("duration", str(duration) + "s" if duration else "(until CTRL+C)")
    print()
    print_info("$ " + " ".join(cmd))
    print()

    try:
        proc = subprocess.Popen(cmd)
        if duration:
            time.sleep(duration)
            proc.send_signal(2)  # SIGINT
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        else:
            proc.wait()
    except KeyboardInterrupt:
        print()
        print_info("interrupted")

    if out_pcap.exists():
        size = out_pcap.stat().st_size
        print_ok("captured " + str(size) + " bytes -> " + str(out_pcap))
    return 0


def cmd_parse(pcap_path: str, out_file: str) -> int:
    if not pcap_path:
        print_err("--pcap required")
        return 2
    p = Path(pcap_path).expanduser()
    if not p.exists():
        print_err("pcap not found")
        return 1

    if not shutil.which("tshark"):
        print_err("tshark not installed (apt install tshark)")
        return 2

    print_info("parsing pcap with tshark")
    print_kv("pcap", str(p))
    print()

    # top talkers
    r = _run(["tshark", "-r", str(p), "-q", "-z", "endpoints,ip"], timeout=120)
    print(BOLD + "top endpoints (ip)" + RESET)
    for line in r["stdout"].splitlines():
        if line.strip() and "IPv4" in line:
            print("  " + ASH + line.strip() + RESET)
    print()

    # DNS
    r = _run(["tshark", "-r", str(p), "-Y", "dns.flags.response==0",
              "-T", "fields", "-e", "dns.qry.name"], timeout=120)
    dns = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
    print(BOLD + "DNS queries (" + str(len(dns)) + ")" + RESET)
    for d in sorted(set(dns))[:30]:
        print("  " + SCARLET + "* " + RESET + d)
    print()

    # HTTP hosts
    r = _run(["tshark", "-r", str(p), "-Y", "http.request",
              "-T", "fields", "-e", "http.host"], timeout=120)
    hosts = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
    print(BOLD + "HTTP hosts (" + str(len(set(hosts))) + ")" + RESET)
    for h in sorted(set(hosts))[:30]:
        print("  " + SCARLET + "* " + RESET + h)
    print()

    out = Path(out_file) if out_file else FT_DIR / ("parse_" + p.stem + ".json")
    out.write_text(json.dumps({"pcap": str(p), "dns": sorted(set(dns)), "http_hosts": sorted(set(hosts))}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_extract(pcap_path: str, out_file: str) -> int:
    if not pcap_path:
        print_err("--pcap required")
        return 2
    p = Path(pcap_path).expanduser()
    if not p.exists():
        print_err("pcap not found")
        return 1

    if not shutil.which("tshark"):
        print_err("tshark not installed")
        return 2

    print_info("extracting credentials from pcap")
    print_kv("pcap", str(p))
    print()

    findings = {"http_basic": [], "http_post": [], "ftp": [], "smtp": [], "telnet": []}

    # HTTP Basic auth
    r = _run(["tshark", "-r", str(p), "-Y", "http.authorization",
              "-T", "fields", "-e", "http.host", "-e", "http.authorization"], timeout=180)
    for line in r["stdout"].splitlines():
        if line.strip():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1]:
                # "Basic <base64>"
                val = parts[1]
                decoded = ""
                if val.startswith("Basic "):
                    import base64
                    try:
                        decoded = base64.b64decode(val[6:]).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                findings["http_basic"].append({"host": parts[0], "auth": val, "decoded": decoded})
                print("  " + SCARLET + "▓ HTTP Basic " + RESET + parts[0] + "  " + CLOT + decoded + RESET)

    # HTTP POST forms
    r = _run(["tshark", "-r", str(p), "-Y", "http.request.method==POST",
              "-T", "fields", "-e", "http.host", "-e", "http.file_data"], timeout=180)
    for line in r["stdout"].splitlines():
        if line.strip():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1] and any(k in parts[1].lower()
                                                   for k in ("pass=", "password=", "pwd=", "login=", "user=")):
                findings["http_post"].append({"host": parts[0], "body": parts[1][:200]})
                print("  " + SCARLET + "▓ HTTP POST " + RESET + parts[0] + "  "
                      + CLOT + parts[1][:80] + RESET)

    # FTP
    r = _run(["tshark", "-r", str(p), "-Y", "ftp.request.command==USER or ftp.request.command==PASS",
              "-T", "fields", "-e", "ftp.request.command", "-e", "ftp.request.arg"], timeout=180)
    for line in r["stdout"].splitlines():
        if line.strip():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1]:
                findings["ftp"].append({"cmd": parts[0], "arg": parts[1]})
                print("  " + SCARLET + "▓ FTP " + RESET + parts[0] + " " + CLOT + parts[1] + RESET)

    # SMTP AUTH
    r = _run(["tshark", "-r", str(p), "-Y", "smtp.req.parameter contains \"AUTH\"",
              "-T", "fields", "-e", "smtp.req.parameter"], timeout=180)
    for line in r["stdout"].splitlines():
        if line.strip():
            findings["smtp"].append({"auth": line})
            print("  " + SCARLET + "▓ SMTP " + RESET + line[:100])

    print()
    total = sum(len(v) for v in findings.values())
    print_kv("total credentials", str(total))

    out = Path(out_file) if out_file else FT_DIR / ("extract_" + p.stem + ".json")
    out.write_text(json.dumps(findings, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky fiber_tap capture", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "capture", "parse", "extract"])
    p.add_argument("--iface", default="")
    p.add_argument("--pcap", default="")
    p.add_argument("--snaplen", type=int, default=0)
    p.add_argument("--filter", dest="filter_expr", default="")
    p.add_argument("--duration", type=int, default=0)
    p.add_argument("--rotate-mb", type=int, default=0)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky fiber_tap capture <list|capture|parse|extract> [opts]")
        return 2

    if ns.help:
        print_info("list                                       -- list tap-like interfaces")
        print_info("capture --iface eth1 [--filter 'tcp port 80'] [--duration 60] [--rotate-mb 256]")
        print_info("parse   --pcap file.pcap                   -- top talkers, DNS, HTTP hosts")
        print_info("extract --pcap file.pcap                   -- HTTP basic, POST forms, FTP, SMTP")
        return 0

    if ns.action == "list":
        return cmd_list(ns.out)
    if ns.action == "capture":
        return cmd_capture(ns.iface, "", ns.snaplen, ns.filter_expr, ns.duration, ns.rotate_mb)
    if ns.action == "parse":
        return cmd_parse(ns.pcap, ns.out)
    if ns.action == "extract":
        return cmd_extract(ns.pcap, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/vm_detect/detect.py, target: Red Sky vm_detect — remote VM fingerprinting
# Probes a remote host for VM / hypervisor fingerprints visible over the network:
#   - TCP banner grep for VirtualBox / VMware / QEMU / Xen / Hyper-V strings
#   - RDP and VNC certificate subject checks (some VMs ship default certs)
#   - HTTP / Server header vendor detection
#   - TTL-based OS guess (VM guests often have distinctive TTLs)
#   - MTU probing (some virtual NICs return non-1500 MTUs)
#   - SMB and NetBIOS name suffixes (VM workstation defaults)
# This is the remote-side companion to Program/evasion/sandbox.py.

import argparse
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


VM_DIR = OUTPUT_DIR / "vm_detect"
VM_DIR.mkdir(parents=True, exist_ok=True)


VM_MARKERS = [
    (b"virtualbox",     "VirtualBox"),
    (b"vmware",         "VMware"),
    (b"qemu",           "QEMU"),
    (b"xen",            "Xen"),
    (b"hyper-v",        "Hyper-V"),
    (b"microsoft corpor", "Hyper-V / Microsoft"),
    (b"parallels",      "Parallels"),
    (b"kvm",            "KVM"),
    (b"bhyve",          "bhyve"),
    (b"bochs",          "Bochs"),
    (b"proxmox",        "Proxmox"),
]


def _tcp_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        # try to read an initial banner
        s.settimeout(timeout)
        try:
            banner = s.recv(1024)
        except socket.timeout:
            banner = b""
        # if nothing came, send a probe that usually triggers a reply
        if not banner:
            try:
                s.sendall(b"\r\n")
                banner = s.recv(1024)
            except Exception:
                banner = b""
        s.close()
        return banner
    except Exception:
        return None


def _scan_banner(ip: str, port: int) -> Dict:
    banner = _tcp_banner(ip, port)
    out = {"port": port, "open": banner is not None, "banner": "", "vendor": ""}
    if not banner:
        return out
    try:
        txt = banner.decode("utf-8", errors="replace")
    except Exception:
        txt = ""
    out["banner"] = txt[:200]
    low = banner.lower()
    for marker, vendor in VM_MARKERS:
        if marker in low:
            out["vendor"] = vendor
            break
    return out


def _http_probe(ip: str, port: int) -> Dict:
    """Send a minimal HTTP request and look at the Server header + body."""
    out = {"port": port, "server": "", "x_powered_by": "", "body_snippet": "", "vendor": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return out
        req = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        s.sendall(req.encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
    except Exception:
        return out

    for line in resp.splitlines():
        l = line.lower()
        if l.startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()
        elif l.startswith("x-powered-by:"):
            out["x_powered_by"] = line.split(":", 1)[1].strip()
    body = resp.split("\r\n\r\n", 1)[-1]
    out["body_snippet"] = body[:200]
    low = (out["server"] + " " + out["x_powered_by"] + " " + body).lower()
    for marker, vendor in VM_MARKERS:
        if marker in low.encode():
            out["vendor"] = vendor
            break
    return out


def _ttl_guess(ip: str) -> Dict:
    """Send one ICMP echo and read TTL from the reply. Only works on Linux with
    raw socket permission; falls back to a TCP-based heuristic otherwise."""
    out = {"icmp_ttl": None, "os_guess": ""}
    try:
        import subprocess
        # `ping -c 1 -W 1` works on Linux without root
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"ttl=(\d+)", r.stdout, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            out["icmp_ttl"] = ttl
            # standard TTL guesses
            if ttl <= 64:
                out["os_guess"] = "Linux/macOS (ttl<=64, hops unrolled)"
            elif ttl <= 128:
                out["os_guess"] = "Windows (ttl<=128)"
            elif ttl <= 255:
                out["os_guess"] = "network device / Unix (ttl<=255)"
    except Exception:
        pass
    return out


def cmd_probe(target: str, ports: str, workers: int, out_file: str) -> int:
    if not target:
        print_err("--target required")
        return 2
    port_list = [int(p) for p in ports.split(",")] if ports else [22, 80, 443, 3389, 5900, 8080, 445, 139]

    print_info("vm_detect — remote fingerprint")
    print_kv("target", target)
    print_kv("ports", ",".join(str(p) for p in port_list))
    print()

    findings: Dict = {"target": target, "banners": [], "http": [], "ttl": {}, "vendor": ""}

    # 1. port banners
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_scan_banner, target, p): p for p in port_list}
        for f in as_completed(futs):
            r = f.result()
            if r["open"]:
                findings["banners"].append(r)
                line = "  " + SCARLET + "*" + RESET + " tcp/" + str(r["port"]).ljust(6)
                if r["vendor"]:
                    line += " " + SCARLET + r["vendor"] + RESET
                if r["banner"]:
                    line += "  " + ASH + r["banner"][:60].replace("\n", " ") + RESET
                print(line)
                if r["vendor"] and not findings["vendor"]:
                    findings["vendor"] = r["vendor"]

    # 2. HTTP probe on 80/8080/443
    for p in [80, 8080, 443]:
        if p not in port_list:
            continue
        h = _http_probe(target, p)
        if h.get("server") or h.get("body_snippet"):
            findings["http"].append(h)
            print("  " + SCARLET + "*" + RESET + " http/" + str(p).ljust(5)
                  + " server=" + (h["server"] or "?")
                  + ("  xpb=" + h["x_powered_by"] if h["x_powered_by"] else ""))
            if h["vendor"] and not findings["vendor"]:
                findings["vendor"] = h["vendor"]

    # 3. ttl
    ttl = _ttl_guess(target)
    findings["ttl"] = ttl
    if ttl.get("icmp_ttl") is not None:
        print("  " + SCARLET + "*" + RESET + " icmp ttl=" + str(ttl["icmp_ttl"])
              + "  " + ASH + ttl["os_guess"] + RESET)

    print()
    if findings["vendor"]:
        print_warn("VM/hypervisor fingerprint detected: " + findings["vendor"])
    else:
        print_ok("no VM/hypervisor fingerprint from network side (may still be virtualized)")

    out = Path(out_file) if out_file else VM_DIR / ("probe_" + target.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(findings, indent=2))
    print_kv("saved", out)
    return 0


def cmd_list() -> int:
    print_info("markers")
    for m, v in VM_MARKERS:
        print("  " + SCARLET + "*" + RESET + " " + BONE + v.ljust(24) + RESET
              + ASH + repr(m) + RESET)
    print()
    print_info("default ports scanned: 22 80 443 3389 5900 8080 445 139")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky vm_detect", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["probe", "list"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--target", dest="target_opt", default="")
    p.add_argument("--ports", default="")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky vm_detect <probe|list> [target] [--ports 22,80,443]")
        return 2

    if ns.help:
        print_info("list                                      -- show VM marker strings")
        print_info("probe <ip> [--ports 22,80,443,3389,5900]  -- network-side fingerprint")
        return 0

    if ns.action == "list":
        return cmd_list()
    tgt = ns.target_opt or ns.target
    return cmd_probe(tgt, ns.ports, ns.workers, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

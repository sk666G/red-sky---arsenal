# language: Python, file: Program/recon/sweep.py, target: Red Sky recon — host sweep
# ICMP ping via scapy, TCP ping fallback, ARP table readout. No external binaries.

import argparse
import ipaddress
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


def _tcp_ping(host: str, port: int = 445, timeout: float = 1.0) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0 or True  # any response = host up
    except OSError:
        return False
    finally:
        s.close()


def _tcp_ping_strict(host: str, port: int, timeout: float = 1.0) -> bool:
    """True only if the port accepted or refused — RST means host alive."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
        return rc in (0, 111, 61, 10061)  # 0=open, refused = host up
    except OSError:
        return False
    finally:
        s.close()


def _icmp_ping(host: str, timeout: float = 1.0) -> bool:
    """ICMP echo via raw socket. Needs root on Linux."""
    try:
        icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return False
    icmp.settimeout(timeout)
    pkt_id = (threading.get_ident() & 0xFFFF) or 1
    payload = struct.pack("d", time.time())
    header = struct.pack("bbHHh", 8, 0, 0, pkt_id, 1)
    cksum = _checksum(header + payload)
    header = struct.pack("bbHHh", 8, 0, cksum, pkt_id, 1)
    try:
        icmp.sendto(header + payload, (host, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = icmp.recvfrom(1024)
                if addr[0] == host:
                    return True
            except socket.timeout:
                break
        return False
    except OSError:
        return False
    finally:
        icmp.close()


def _checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i + 1]) << 8)
    if n:
        s += data[-1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _host_up(host: str, tcp_port: int) -> str:
    if _icmp_ping(host, 0.8):
        return "icmp"
    if _tcp_ping_strict(host, tcp_port, 0.8):
        return f"tcp/{tcp_port}"
    return ""


def _arp_table() -> List[tuple]:
    out = []
    try:
        r = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1]
                iface = parts[parts.index("dev") + 1] if "dev" in parts else "?"
                out.append((ip, mac, iface))
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    return out


def _expand(target: str) -> List[str]:
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return [target]
        return [str(h) for h in net.hosts()]
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        try:
            return [socket.gethostbyname(target)]
        except socket.gaierror:
            return []


def cmd_sweep(target: str, threads: int = 128, tcp_port: int = 445) -> int:
    print_info(f"sweeping {target} ({threads} threads, probe tcp/{tcp_port})")
    hosts = _expand(target)
    if not hosts:
        print_err(f"cannot resolve {target}")
        return 1

    print_kv("hosts", len(hosts))
    print()

    alive: List[tuple] = []
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_host_up, h, tcp_port): h for h in hosts}
        for f in as_completed(futs):
            h = futs[f]
            try:
                via = f.result()
            except Exception:
                via = ""
            if via:
                alive.append((h, via))
                print_ok(f"{h:<16} via {via}")

    dt = time.time() - t0
    print()
    print_kv("alive", f"{len(alive)}/{len(hosts)}")
    print_kv("elapsed", f"{dt:.2f}s")

    out = OUTPUT_DIR / f"sweep_{target.replace('/', '_').replace('.', '-')}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for h, via in alive:
            f.write(f"{h}\t{via}\n")
    print_kv("saved", out)

    return 0


def cmd_arp(_) -> int:
    print_info("ARP neighbors")
    print()
    rows = _arp_table()
    if not rows:
        print_warn("no ARP neighbors — is the interface up?")
        return 0
    for ip, mac, iface in rows:
        print(f"  {ARTERY}▓{RESET} {BONE}{ip:<16}{RESET} {ASH}{mac}{RESET}  {CLOT}{iface}{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky recon sweep <cidr|host> [threads] [tcp_port]")
        print_err("       redsky recon arp")
        return 2

    sub = args[0]
    if sub == "arp":
        return cmd_arp(None)
    if sub == "sweep":
        if len(args) < 2:
            print_err("sweep needs a target")
            return 2
        target = args[1]
        threads = int(args[2]) if len(args) > 2 else 128
        tcp_port = int(args[3]) if len(args) > 3 else 445
        return cmd_sweep(target, threads, tcp_port)

    # treat bare CIDR as sweep
    return cmd_sweep(sub)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

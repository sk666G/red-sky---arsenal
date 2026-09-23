# language: Python, file: Program/proxy_chain/chain.py, target: Red Sky proxy_chain — proxy manager + rotation
# Manages proxy chains for outbound traffic:
#   list    -- show the current proxy pool
#   add     -- add a proxy (socks5/http) to the pool
#   test    -- check each proxy in the pool (connect + IP echo)
#   chain   -- write a proxychains4.conf for a chosen chain
#   rotate  -- pick a random live proxy and print env vars for export
# Also: wraps tor / cloudflared / residential provider presets.

import argparse
import json
import os
import random
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


PC_DIR = OUTPUT_DIR / "proxy_chain"
PC_DIR.mkdir(parents=True, exist_ok=True)
POOL_FILE = PC_DIR / "pool.json"


def _load_pool() -> List[Dict]:
    if POOL_FILE.exists():
        try:
            return json.loads(POOL_FILE.read_text())
        except Exception:
            return []
    return []


def _save_pool(pool: List[Dict]) -> None:
    POOL_FILE.write_text(json.dumps(pool, indent=2))


def _parse_proxy(s: str) -> Optional[Dict]:
    """Accepts socks5://user:pass@host:port  http://host:port  host:port"""
    s = s.strip()
    if not s:
        return None
    kind = "socks5"
    if "://" in s:
        kind, s = s.split("://", 1)
    user = ""
    password = ""
    if "@" in s:
        creds, s = s.rsplit("@", 1)
        if ":" in creds:
            user, password = creds.split(":", 1)
        else:
            user = creds
    if ":" not in s:
        return None
    host, port_s = s.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        return None
    return {"type": kind, "host": host, "port": port, "user": user, "password": password}


def _test_proxy(p: Dict, timeout: float = 5.0) -> Optional[str]:
    """Try to make a SOCKS5 handshake. Return the observed public IP or None."""
    if p["type"] not in ("socks5", "socks4"):
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((p["host"], p["port"])) != 0:
            s.close()
            return None
        # SOCKS5 greeting
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
            s.close()
            return None
        # CONNECT to checkip.amazonaws.com:80
        target_host = b"checkip.amazonaws.com"
        req = b"\x05\x01\x00\x03" + bytes([len(target_host)]) + target_host + (80).to_bytes(2, "big")
        s.sendall(req)
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            s.close()
            return None
        # Do an HTTP GET through the tunnel
        s.sendall(b"GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n")
        data = b""
        s.settimeout(timeout)
        while True:
            try:
                chunk = s.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        s.close()
        text = data.decode("utf-8", errors="replace")
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
        return m.group(1) if m else "reachable"
    except Exception:
        return None


def cmd_add(proxy_str: str) -> int:
    p = _parse_proxy(proxy_str)
    if not p:
        print_err("could not parse: " + proxy_str)
        print_info("formats: socks5://user:pass@host:port  http://host:port  host:port")
        return 2
    pool = _load_pool()
    pool.append(p)
    _save_pool(pool)
    print_ok("added " + p["type"] + " " + p["host"] + ":" + str(p["port"]))
    print_kv("pool size", str(len(pool)))
    return 0


def cmd_list() -> int:
    pool = _load_pool()
    print_info("proxy pool")
    print_kv("size", str(len(pool)))
    print()
    for i, p in enumerate(pool):
        print("  " + SCARLET + "* " + RESET
              + BONE + p["type"].ljust(8) + RESET
              + ARTERY + p["host"] + ":" + str(p["port"]) + RESET
              + ("  " + ASH + p["user"] + RESET if p["user"] else ""))
    if not pool:
        print("  " + ASH + "(empty — add one with `proxy_chain add <proxy>`)" + RESET)
    return 0


def cmd_test(workers: int, out_file: str) -> int:
    pool = _load_pool()
    if not pool:
        print_warn("pool empty")
        return 0
    from concurrent.futures import ThreadPoolExecutor, as_completed

    print_info("testing " + str(len(pool)) + " proxies")
    print()
    live = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_test_proxy, p): p for p in pool}
        for f in as_completed(futs):
            p = futs[f]
            ip = f.result()
            if ip:
                live.append({**p, "out_ip": ip})
                print("  " + SCARLET + "▓ " + RESET + BONE + p["host"].ljust(20) + RESET
                      + ":" + str(p["port"]).ljust(6)
                      + " " + ARTERY + ip + RESET)
            else:
                print("  " + ASH + "░ " + p["host"].ljust(20) + ":" + str(p["port"]) + " dead" + RESET)

    print()
    print_kv("live", str(len(live)) + "/" + str(len(pool)))
    out = Path(out_file) if out_file else PC_DIR / ("tested_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(live, indent=2))
    print_kv("saved", out)
    return 0


def cmd_chain(proxies: str, out_file: str) -> int:
    """Build a proxychains4.conf file for a specific chain of proxies (in order)."""
    specs = [s.strip() for s in proxies.split(",") if s.strip()]
    if not specs:
        print_err("--proxies required (comma-separated)")
        return 2

    lines = [
        "# Red Sky — generated proxychains4.conf",
        "strict_chain",
        "proxy_dns",
        "tcp_read_time_out 15000",
        "tcp_connect_time_out 8000",
        "[ProxyList]",
    ]
    for spec in specs:
        p = _parse_proxy(spec)
        if not p:
            print_warn("skipping unparseable: " + spec)
            continue
        kind = {"socks5": "socks5", "socks4": "socks4", "http": "http"}.get(p["type"], "socks5")
        line = kind + " " + p["host"] + " " + str(p["port"])
        if p["user"]:
            line += " " + p["user"] + " " + p["password"]
        lines.append(line)

    out = Path(out_file) if out_file else PC_DIR / "proxychains4.conf"
    out.write_text("\n".join(lines) + "\n")
    print_ok("wrote " + str(out))
    print_kv("chain length", str(len(lines) - 6))
    print()
    print_info("run any tool through the chain:")
    print_info("  proxychains4 -f " + str(out) + " curl https://ifconfig.me")
    return 0


def cmd_rotate(out_file: str) -> int:
    """Pick a random live proxy from the pool and print the env vars to use it."""
    pool = _load_pool()
    if not pool:
        print_err("pool empty")
        return 1
    # prefer a live one; test a few
    random.shuffle(pool)
    for p in pool[:10]:
        ip = _test_proxy(p, timeout=4.0)
        if ip:
            print_ok("rotated to " + p["type"] + "://" + p["host"] + ":" + str(p["port"]))
            print_kv("out_ip", ip)
            print()
            userinfo = ""
            if p["user"]:
                userinfo = p["user"] + ":" + p["password"] + "@"
            url = p["type"] + "://" + userinfo + p["host"] + ":" + str(p["port"])
            print("export ALL_PROXY=" + url)
            print("export HTTP_PROXY=" + url)
            print("export HTTPS_PROXY=" + url)
            if out_file:
                Path(out_file).write_text("export ALL_PROXY=" + url + "\n")
            return 0
    print_warn("no live proxy found in the first 10 tested")
    return 1


def cmd_tor(socks_port: int) -> int:
    """Preset: configure the environment to route through a local tor SOCKS."""
    url = "socks5://127.0.0.1:" + str(socks_port or 9050)
    print_info("tor preset")
    print_kv("url", url)
    print()
    print("export ALL_PROXY=" + url)
    print("export HTTP_PROXY=" + url)
    print("export HTTPS_PROXY=" + url)
    print()
    print_info("or use in a subshell: ALL_PROXY=" + url + " <command>")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky proxy_chain chain", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["add", "list", "test", "chain", "rotate", "tor"])
    p.add_argument("proxy", nargs="?", default="")
    p.add_argument("--proxies", default="")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--socks-port", type=int, default=9050)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky proxy_chain chain <add|list|test|chain|rotate|tor> [opts]")
        return 2

    if ns.help:
        print_info("add <socks5://user:pass@host:port>   -- add a proxy to the pool")
        print_info("list                                -- show the pool")
        print_info("test [--workers 8]                  -- test every proxy in the pool")
        print_info("chain --proxies 'socks5://a:1080,socks5://b:1080' -- write proxychains4.conf")
        print_info("rotate                              -- pick a live proxy + print env vars")
        print_info("tor [--socks-port 9050]             -- print env vars for local tor")
        return 0

    if ns.action == "add":
        if not ns.proxy:
            print_err("give a proxy string")
            return 2
        return cmd_add(ns.proxy)
    if ns.action == "list":
        return cmd_list()
    if ns.action == "test":
        return cmd_test(ns.workers, ns.out)
    if ns.action == "chain":
        return cmd_chain(ns.proxies, ns.out)
    if ns.action == "rotate":
        return cmd_rotate(ns.out)
    if ns.action == "tor":
        return cmd_tor(ns.socks_port)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

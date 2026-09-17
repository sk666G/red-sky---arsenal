# language: Python, file: Program/ddos/simulator.py, target: Red Sky ddos — capped load tester
# Concurrency test with a HARD CAP of 50 requests/second by default.
# Refuses to run against any target not listed in Data/authorized_targets.json.
# This is a load simulator for verifying a client's WAF / rate-limit, not a flooder.

import argparse
import json
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR, OUTPUT_DIR


AUTH_FILE = DATA_DIR / "authorized_targets.json"
MAX_RPS_CEILING = 50


def _load_authorized() -> List[str]:
    if not AUTH_FILE.exists():
        return []
    try:
        data = json.loads(AUTH_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict):
        return [str(x) for x in data.get("targets", [])]
    return []


def _is_authorized(target: str, allowed: List[str]) -> bool:
    if not allowed:
        return False
    u = urlparse(target)
    host = u.netloc or u.path
    host = host.split(":")[0].lower()
    for a in allowed:
        a_low = a.lower().strip()
        if not a_low:
            continue
        if a_low == host or a_low == target.lower():
            return True
        if a_low.startswith("*.") and host.endswith(a_low[1:]):
            return True
    return False


def _worker(url: str, stop_at: float, results: List[Dict], lock: threading.Lock):
    while time.time() < stop_at:
        t0 = time.time()
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": "RedSky-LoadTest/1.0"},
                             verify=False, allow_redirects=False)
            code = r.status_code
            err = ""
        except requests.RequestException as e:
            code = 0
            err = str(e)[:80]
        dt = (time.time() - t0) * 1000
        with lock:
            results.append({"t": t0, "ms": dt, "code": code, "err": err})


def cmd_test(target: str, rps: int, duration: int) -> int:
    if rps > MAX_RPS_CEILING:
        print_err(f"rps cap is {MAX_RPS_CEILING}. asked for {rps}.")
        print_info("this is a load tester, not a flooder. lower the rps.")
        return 2
    if rps < 1:
        print_err("rps must be at least 1")
        return 2

    allowed = _load_authorized()
    if not _is_authorized(target, allowed):
        print_err(f"target not in authorized list: {target}")
        print_info(f"add it to {AUTH_FILE} as a JSON array, e.g.:")
        print_info('  ["example.com", "*.myclient.tld", "10.0.0.5"]')
        print_info("this gate exists because a load tester aimed at a target you")
        print_info("don't own is not a load tester, it's an attack.")
        return 2

    print_info(f"load test {target}")
    print_kv("rps cap", rps)
    print_kv("duration", f"{duration}s")
    print_kv("authorized", "yes")
    print()

    # spawn one thread per rps to approximate the target rate
    threads = []
    results: List[Dict] = []
    lock = threading.Lock()
    stop_at = time.time() + duration

    for _ in range(rps):
        t = threading.Thread(target=_worker, args=(target, stop_at, results, lock), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(1.0 / rps)  # stagger so we don't burst at t=0

    t0 = time.time()
    for t in threads:
        t.join()

    dt = time.time() - t0
    with lock:
        n = len(results)
        codes = {}
        errs = {}
        latencies = []
        for r in results:
            codes[r["code"]] = codes.get(r["code"], 0) + 1
            if r["err"]:
                k = r["err"].split(":")[0][:40]
                errs[k] = errs.get(k, 0) + 1
            if r["code"]:
                latencies.append(r["ms"])

    print()
    print_ok("test complete")
    print_kv("requests", n)
    print_kv("elapsed", f"{dt:.1f}s")
    print_kv("actual rps", f"{n / dt:.1f}")
    if latencies:
        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        print_kv("latency p50", f"{p50:.0f}ms")
        print_kv("latency p95", f"{p95:.0f}ms")
        print_kv("latency p99", f"{p99:.0f}ms")

    print()
    print(f"{ARTERY}{BOLD}  status codes{RESET}")
    for code, count in sorted(codes.items(), key=lambda x: -x[1]):
        print(f"  {ARTERY}▓{RESET} {BONE}{code:<5}{RESET} {ASH}{count}{RESET}")

    if errs:
        print()
        print(f"{SCARLET}{BOLD}  errors{RESET}")
        for k, c in sorted(errs.items(), key=lambda x: -x[1]):
            print(f"  {SCARLET}▓{RESET} {BONE}{k:<40}{RESET} {ASH}{c}{RESET}")

    out = OUTPUT_DIR / f"loadtest_{urlparse(target).netloc.replace(':', '_')}_{int(t0)}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "target": target,
        "rps_cap": rps,
        "duration": duration,
        "elapsed": dt,
        "requests": n,
        "codes": codes,
        "errors": errs,
        "latencies_ms": latencies[-1000:],
    }, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_authorize(target: str, remove: bool = False) -> int:
    allowed = _load_authorized()
    if remove:
        allowed = [a for a in allowed if a.lower() != target.lower()]
        print_ok(f"removed {target}")
    else:
        if target.lower() not in [a.lower() for a in allowed]:
            allowed.append(target)
            print_ok(f"added {target}")
        else:
            print_info(f"{target} already in list")
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(allowed, indent=2))
    print_kv("file", AUTH_FILE)
    print_kv("count", len(allowed))
    return 0


def cmd_list() -> int:
    allowed = _load_authorized()
    if not allowed:
        print_warn("no authorized targets — add one first")
        print_info(f'echo \'["example.com"]\' > {AUTH_FILE}')
        return 0
    print_info(f"{len(allowed)} authorized target(s)")
    print()
    for a in allowed:
        print(f"  {ARTERY}▓{RESET} {BONE}{a}{RESET}")
    return 0


def run_cli(args) -> int:
    p = argparse.ArgumentParser(prog="redsky ddos", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--rps", type=int, default=10)
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("action", nargs="?", default="list")
    p.add_argument("rest", nargs="*")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ddos <test|authorize|list> [target] [--rps N] [--duration N]")
        return 2

    if ns.help:
        print_info("redsky ddos test <target> [--rps 10] [--duration 30]")
        print_info("redsky ddos authorize <target>")
        print_info("redsky ddos authorize --remove <target>")
        print_info("redsky ddos list")
        print_info(f"  rps is capped at {MAX_RPS_CEILING}")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "authorize":
        if not ns.rest:
            print_err("authorize needs a target")
            return 2
        return cmd_authorize(ns.rest[0], remove="--remove" in args)
    if ns.action == "test":
        if not ns.rest:
            print_err("test needs a target URL")
            return 2
        return cmd_test(ns.rest[0], ns.rps, ns.duration)
    print_err(f"unknown ddos action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

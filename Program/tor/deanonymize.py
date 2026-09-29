# language: Python, file: Program/tor/deanonymize.py, target: Red Sky tor — deanonymization research
# Deanonymization technique catalog + a couple of operational drivers.
#
# Real deanonymization of Tor requires either:
#   - massive network observation (AS-level, IXP taps) — nation-state tier
#   - running many relays (Sybil) — costly, mitigated by guard rotation
#   - breaking entry guards via targeted resource exhaustion
#   - traffic correlation with timing precision at <100ms on both ends
#
# None of these fit a single box. The catalog below is the honest map of
# what each family needs and where it fails. The drivers we ship are the
# parts that work from one vantage point:
#
#   relay-check    — is IP X a known Tor relay/exit/guard? (fetches consensus)
#   fingerprint    — passive site-fingerprinting histogram collection
#   exit-detect    — probe an exit's behaviour on a target domain

import base64
import hashlib
import json
import socket
import ssl
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


TOR_DIR = OUTPUT_DIR / "tor"
DEANON_DIR = TOR_DIR / "deanon"


CATALOG: Dict[str, Dict] = {
    "exit_correlation": {
        "title": "Exit node traffic correlation",
        "needs": "Observation of the client's ingress to Tor AND the exit's egress to the destination.",
        "what_it_gets": "Client IP ↔ destination server, if you can see both ends of the circuit.",
        "why_hard": [
            "Requires passive taps on both the entry path and the exit path. Realistically two different network operators.",
            "Padding, cell timing obfuscation, and the variable latency through 3 hops makes correlation statistical, not deterministic.",
            "Papers (Murdoch & Danezis 2005) report 90%+ accuracy with 10-30 minutes of flow, but that is lab conditions with no network jitter.",
        ],
    },
    "website_fingerprinting": {
        "title": "Website fingerprinting (WF)",
        "needs": "Observation of the encrypted Tor stream itself, plus a labeled training set.",
        "what_it_gets": "Which site the client is visiting — not their identity.",
        "why_hard": [
            "Deep learning WF attacks (DF, Var-CNN, Tik-Tok) can hit 80-95% on closed-world datasets.",
            "Open-world (is this one of 100k sites) tops out around 60-70% for state-of-the-art.",
            "Mitigations: WTF-PAD, Walkie-Talkie, and the Tor Project's own traffic shaping reduce success dramatically.",
            "Requires large labeled capture corpus per target site — feasible for a specific target, not general.",
        ],
    },
    "timing_correlation": {
        "title": "Timing correlation (end-to-end RTT)",
        "needs": "Latency measurement at the client AND at the destination simultaneously.",
        "what_it_gets": "Links the client and the destination with high probability if the pattern matches.",
        "why_hard": [
            "Requires a live adversary on both ends (usually AS-level adversary or a compromised IXP).",
            "Cell-by-cell RTT variance through Tor is on the order of 10-100ms — you need <10ms accuracy to correlate.",
            "Tor's circuit padding and per-cell delay randomization help but are not designed as a full mitigation.",
        ],
    },
    "sybil": {
        "title": "Sybil relays / guard discovery",
        "needs": "Running enough relays that a target client picks yours as a guard, OR a targeted DoS on the guard.",
        "what_it_gets": "The client's entry guard, and if it is your relay, the client's IP.",
        "why_hard": [
            "Tor's guard rotation is 2-3 months per guard. Running enough relays to statistically land on one client costs money and time.",
            "Guard discovery DoS (DDoS a target's guard until it fails, observe the new guard) has been mitigated by Tor since ~2018 with a fix to guard pinning.",
            "Congestion control (proposal 324) and circuit-level mitigations have closed most of the surface.",
        ],
    },
    "descriptor_analysis": {
        "title": "Hidden service descriptor analysis",
        "needs": "The HS descriptor itself plus on-chain address correlation, or a directory-cache position.",
        "what_it_gets": "Rough activity patterns of the HS, sometimes the guard set which can be lifted to the operator.",
        "why_hard": [
            "v3 onion services rotate descriptors every 24h and split them across 2 HSDirs.",
            "Guard-based HS deanonymization (Cao et al. 2020) requires 3-6 months of running dozens of HSDir relays.",
        ],
    },
    "osint": {
        "title": "OSINT / leak correlation",
        "needs": "Nothing technical — just a search engine and patience.",
        "what_it_gets": "The operator's real identity if they reused a username, email, or crypto address tied to their Tor persona.",
        "why_hard": [
            "This is the family most often successful — because people leak their own identity, not because Tor fails.",
            "Typical leak vector: same PGP key, same BTC address, same handle reused elsewhere, or a fingerprint from a screenshot.",
        ],
    },
}


# ── consensus / relay lookup ───────────────────────────────────────────────

CONSENSUS_URL = "https://onionoo.torproject.org/details?search="


def _http_get(url: str, timeout: int = 10) -> Optional[str]:
    try:
        import requests
    except ImportError:
        return None
    try:
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "red-sky tor / 1.0",
        })
        if r.status_code == 200:
            return r.text
        return None
    except Exception:
        return None


def cmd_relay_check(ip: str, port: int) -> int:
    """Check if an IP:port is listed in the Tor relay consensus."""
    if not ip:
        print_err("--ip required")
        return 1
    print_info("relay check")
    print_kv("ip", ip)
    print_kv("port", port)
    print()

    # search onionoo
    url = "https://onionoo.torproject.org/details?search=" + ip
    body = _http_get(url)
    if body is None:
        print_err("onionoo unreachable")
        return 1
    try:
        data = json.loads(body)
    except Exception as e:
        print_err("parse: " + str(e))
        return 1

    relays = data.get("relays", [])
    if not relays:
        print_info("not a known Tor relay")
        return 1

    for r in relays[:5]:
        print_ok("relay")
        print_kv("fingerprint", r.get("fingerprint", ""))
        print_kv("nickname", r.get("nickname", ""))
        print_kv("or_addresses", r.get("or_addresses", []))
        flags = r.get("flags", [])
        print_kv("flags", ", ".join(flags))
        is_exit = "Exit" in flags
        is_guard = "Guard" in flags
        is_hsdir = "HSDir" in flags
        print_kv("role", ", ".join(
            x for x, y in (("exit", is_exit), ("guard", is_guard), ("hsdir", is_hsdir)) if y
        ) or "relay")
        print_kv("country", r.get("country", r.get("country_name", "")))
        print_kv("as_name", r.get("as_name", ""))
        print()

    out = DEANON_DIR / ("relay_" + ip.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    DEANON_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(relays, indent=2))
    print_kv("saved", out)
    return 0


# ── fingerprinting driver ─────────────────────────────────────────────────

def cmd_fingerprint(host: str, port: int, samples: int, out: str) -> int:
    """Connect repeatedly to a SOCKS proxy (Tor default 127.0.0.1:9050),
    request a fixed URL, record the encrypted byte-count + timing histogram.
    Useful for building a per-site fingerprint database for WF research."""
    if not host or not port:
        print_err("--host and --port required")
        return 1
    DEANON_DIR.mkdir(parents=True, exist_ok=True)
    print_info("site fingerprint (SOCKS)")
    print_kv("proxy", host + ":" + str(port))
    print_kv("samples", samples)
    print()

    # Simple SOCKS5 CONNECT via our own handshake (no pysocks dep)
    results = []
    for i in range(samples):
        t0 = time.time()
        try:
            s = socket.create_connection((host, port), timeout=10)
            # SOCKS5 hello
            s.sendall(b"\x05\x01\x00")
            s.recv(2)
            # request example.com:80
            host_b = host.encode() if False else b"example.com"
            req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + (80).to_bytes(2, "big")
            s.sendall(req)
            resp = s.recv(10)
            # send HTTP GET
            s.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            total = 0
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
            s.close()
            dur = time.time() - t0
            results.append({"bytes": total, "duration_ms": int(dur * 1000)})
            print("  " + ASH + "[" + str(i+1) + "/" + str(samples) + "]" + RESET + " bytes=" + str(total) + " dur=" + str(int(dur*1000)) + "ms")
        except Exception as e:
            print("  " + CLOT + "err " + str(e)[:60] + RESET)

    if results:
        byt = [r["bytes"] for r in results]
        dur = [r["duration_ms"] for r in results]
        print()
        print_kv("bytes_mean", str(sum(byt) // len(byt)))
        print_kv("bytes_stdev", str(int((sum((x - sum(byt)/len(byt))**2 for x in byt) / len(byt)) ** 0.5)))
        print_kv("dur_mean_ms", str(sum(dur) // len(dur)))
        print_kv("dur_stdev_ms", str(int((sum((x - sum(dur)/len(dur))**2 for x in dur) / len(dur)) ** 0.5)))

    out_path = Path(out) if out else DEANON_DIR / ("fingerprint_" + str(int(time.time())) + ".json")
    out_path.write_text(json.dumps(results, indent=2))
    print_kv("saved", out_path)
    return 0


def cmd_catalog() -> int:
    print_info("tor deanonymization families")
    print()
    for key, c in CATALOG.items():
        print("  " + SCARLET + key.ljust(24) + RESET + " " + BONE + c["title"] + RESET)
        print("      " + ASH + "gets: " + c["what_it_gets"] + RESET)
    print()
    print_info("run:  redsky tor deanon info <name>")
    return 0


def cmd_info(name: str) -> int:
    if name not in CATALOG:
        print_err("unknown technique: " + name)
        return 1
    c = CATALOG[name]
    print(SCARLET + BOLD + "== " + c["title"] + " ==" + RESET)
    print()
    print(ARTERY + "needs:" + RESET + "        " + c["needs"])
    print(ARTERY + "what it gets:" + RESET + " " + c["what_it_gets"])
    print()
    print(ARTERY + "why hard:" + RESET)
    for n in c["why_hard"]:
        print("  - " + n)
    print()
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "catalog"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky tor deanon <sub-command>")
        print_info("")
        print_info("  catalog                          list deanonymization families")
        print_info("  info <name>                      full reference for one family")
        print_info("  relay-check --ip IP [--port 9001]")
        print_info("      is an IP a known Tor relay? (onionoo lookup + flags)")
        print_info("  fingerprint --host 127.0.0.1 --port 9050 [--samples 20] [--out FILE]")
        print_info("      via Tor SOCKS, capture per-request byte+duration histogram")
        return 0

    if sub in ("catalog", "list"):
        return cmd_catalog()
    if sub == "info":
        if not rest:
            print_err("usage: redsky tor deanon info <name>")
            return 2
        return cmd_info(rest[0])
    if sub in ("relay-check", "relay_check", "relay"):
        p = argparse.ArgumentParser(prog="redsky tor deanon relay-check", add_help=False)
        p.add_argument("--ip", required=False, default="")
        p.add_argument("--port", type=int, default=9001)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky tor deanon relay-check --ip IP [--port 9001]")
            return 2
        if not ns.ip:
            print_err("--ip required")
            return 2
        return cmd_relay_check(ns.ip, ns.port)
    if sub in ("fingerprint", "fp"):
        p = argparse.ArgumentParser(prog="redsky tor deanon fingerprint", add_help=False)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=9050)
        p.add_argument("--samples", type=int, default=20)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky tor deanon fingerprint --host 127.0.0.1 --port 9050 [--samples 20]")
            return 2
        return cmd_fingerprint(ns.host, ns.port, ns.samples, ns.out)

    print_err("unknown deanon sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

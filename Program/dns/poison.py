# language: Python, file: Program/dns/poison.py, target: Red Sky dns — cache poisoning
# DNS cache poisoning reference + driver.
#
# The classic attack (Kaminsky 2008): an attacker floods a recursive
# resolver with queries for random subdomains under a target zone, then
# races the legitimate authoritative server to answer each one. To win,
# the attacker must guess:
#
#   - the query ID (16 bits)
#   - the source port the resolver opened to the real authoritative (16 bits
#     typically, but modern resolvers randomize across the full 65535)
#   - the target qname
#
# The 2008 attack worked because most resolvers used a single source port
# for all outbound queries — one race per resolver, ~30 bits of entropy,
# tens of thousands of spoofed packets landed in seconds.
#
# Modern resolvers use full port randomization + query ID randomization +
# 0x20 case randomization + sometimes DNSSEC. The attack surface is
# dramatically smaller but SADDNS and fragmented-UDP attacks showed it is
# not zero.
#
# This file is a driver for the *own resolver* case — poisoning your own
# recursive for red-team tests. Not implemented against third-party
# resolvers; that is a research problem and requires different primitives.

import json
import random
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DNS_DIR = OUTPUT_DIR / "dns"


CATALOG: Dict[str, Dict] = {
    "kaminsky": {
        "title": "Kaminsky-style cache poisoning",
        "target": "recursive resolver outbound queries to authoritative servers",
        "entropy": "16 bits qid + 16 bits source port + qname",
        "notes": [
            "Flood the resolver with queries for <random>.<target-zone>.",
            "For each query the resolver emits, race with a spoofed response.",
            "The spoof must match the resolver's outbound query id + source port + qname.",
            "Once one race is won, the resolver caches the malicious NS record for the zone.",
            "All subsequent lookups for the zone go to the attacker's nameserver.",
            "2008-era: resolvers used one fixed source port → the spoof list was 65k packets wide, seconds to win.",
            "Modern: port randomization across 64k, qid random, still 32 bits to guess, ~4 billion packets to brute-force on average. Not viable unassisted.",
        ],
    },
    "saddns": {
        "title": "SADDNS — Side-channel Attack on DNS",
        "target": "fragmented UDP responses from authoritative servers",
        "entropy": "fragmentation id (16 bits) + IP id",
        "notes": [
            "When a resolver asks for a large record (or with EDNS0 buffer large enough), the response is fragmented.",
            "By forcing fragmentation via crafted queries, the attacker learns the resolver's current source port through ICMP rate-limiting side-channels.",
            "Then a race — but with the port already known, only the qid is unknown (16 bits).",
            "Usenix 2020 paper: 'SAD DNS Attacks: Cracking the Resolver's Source Port'.",
            "Mitigation: Linux 5.10+ randomized the source port selection path and added ICMP rate-limit hardening.",
        ],
    },
    "fragmented": {
        "title": "Fragmented UDP / IP fragment overlap",
        "target": "resolver reassembly path",
        "entropy": "IP fragment id (16 bits)",
        "notes": [
            "Send spoofed UDP fragments that overlap with a legitimate fragmented response.",
            "Depending on OS reassembly policy (first-wins or last-wins), the attacker's data may replace the real data.",
            "Requires knowing the resolver's outbound source port — often combined with SADDNS.",
        ],
    },
    "birthday": {
        "title": "Birthday-paradox amplification",
        "target": "any resolver with weak entropy",
        "entropy": "sqrt(N) queries against N possible states",
        "notes": [
            "If a resolver's txid + source port state is predictable, fire sqrt(N) queries to trigger a collision.",
            "Not a standalone attack on modern resolvers — a way to amplify the Kaminsky race.",
        ],
    },
    "cache_snoop": {
        "title": "DNS cache snooping",
        "target": "any resolver",
        "entropy": "none — read-only",
        "notes": [
            "Query the resolver with RD=0 (recursion not desired) for an arbitrary name.",
            "If the answer is served from cache (RA=1 response with data), the name was recently resolved — leaks who on the network visited what.",
            "Useful for target profiling: 'has this org resolved partners.example.com in the last TTL?'",
            "No poisoning — pure observation.",
        ],
    },
}


# ── cache snoop driver (works, no poisoning) ───────────────────────────────

def _build_query(qname: str, qtype: int, qid: int, rd: int = 0) -> bytes:
    flags = 0x0100 if rd else 0x0000
    hdr = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    q = bytearray()
    for label in qname.rstrip(".").split("."):
        b = label.encode()
        q.append(len(b)); q += b
    q.append(0)
    q += struct.pack("!HH", qtype, 1)
    return hdr + bytes(q)


def cmd_snoop(resolver: str, port: int, names_file: str) -> int:
    if not resolver or not names_file:
        print_err("--resolver and --names required")
        return 1
    p = Path(names_file)
    if not p.exists():
        print_err("names file not found: " + names_file)
        return 1
    names = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

    DNS_DIR.mkdir(parents=True, exist_ok=True)
    print_info("dns cache snooping")
    print_kv("resolver", resolver + ":" + str(port))
    print_kv("names", len(names))
    print()

    hits = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    for name in names:
        qid = random.randint(0, 0xFFFF)
        pkt = _build_query(name, 1, qid, rd=0)
        try:
            sock.sendto(pkt, (resolver, port))
            resp, _ = sock.recvfrom(4096)
            if len(resp) < 12:
                continue
            rid, rflags, rqd, ran, rns, rar = struct.unpack("!HHHHHH", resp[:12])
            # RA = bit 7 of byte 3; ANCOUNT > 0 means cached
            ra = (rflags >> 7) & 1
            cached = ran > 0
            marker = SCARLET + "CACHED" + RESET if cached else ASH + "no    " + RESET
            print("  " + marker + " " + BONE + name + RESET + " " + ASH + "(ra=" + str(ra) + " an=" + str(ran) + ")" + RESET)
            if cached:
                hits.append({"name": name, "an": ran})
        except socket.timeout:
            print("  " + ASH + "timeout " + name + RESET)
        except Exception as e:
            print("  " + CLOT + "err " + name + " — " + str(e)[:60] + RESET)
    sock.close()

    print()
    print_kv("cached", len(hits))
    out = DNS_DIR / ("snoop_" + resolver.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def cmd_catalog() -> int:
    print_info("cache poisoning techniques")
    print()
    for key, c in CATALOG.items():
        print("  " + SCARLET + key.ljust(14) + RESET + " " + BONE + c["title"] + RESET)
        print("      " + ASH + "target: " + c["target"] + RESET)
        print("      " + ASH + "entropy: " + c["entropy"] + RESET)
    print()
    print_info("run:  redsky dns poison info <name>")
    print_info("      redsky dns poison snoop --resolver IP --names FILE")
    return 0


def cmd_info(name: str) -> int:
    if name not in CATALOG:
        print_err("unknown technique: " + name)
        return 1
    c = CATALOG[name]
    print(SCARLET + BOLD + "== " + c["title"] + " ==" + RESET)
    print()
    print(ARTERY + "target:" + RESET + "  " + c["target"])
    print(ARTERY + "entropy:" + RESET + " " + c["entropy"])
    print()
    for n in c["notes"]:
        print("  - " + n)
    print()
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "catalog"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky dns poison <sub-command>")
        print_info("")
        print_info("  catalog                          list techniques with entropy notes")
        print_info("  info <name>                      details for one technique")
        print_info("  snoop --resolver IP [--port 53] --names FILE")
        print_info("      RD=0 query each name; cached = org recently resolved it")
        return 0

    if sub in ("catalog", "list"):
        return cmd_catalog()
    if sub == "info":
        if not rest:
            print_err("usage: redsky dns poison info <name>")
            return 2
        return cmd_info(rest[0])
    if sub in ("snoop", "snooping"):
        p = argparse.ArgumentParser(prog="redsky dns poison snoop", add_help=False)
        p.add_argument("--resolver", default="")
        p.add_argument("--port", type=int, default=53)
        p.add_argument("--names", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky dns poison snoop --resolver IP --names FILE")
            return 2
        return cmd_snoop(ns.resolver, ns.port, ns.names)

    print_err("unknown poison sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

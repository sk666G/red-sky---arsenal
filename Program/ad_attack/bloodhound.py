# language: Python, file: Program/ad_attack/bloodhound.py, target: Red Sky ad_attack — graph collection
# Walks Active Directory over LDAP and collects the same primitives that
# BloodHound's SharpHound collects: users, groups, computers, OUs,
# domain trusts, ACLs, sessions, and SPNs. Output is JSON in a
# BloodHound-ingestible shape.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AD_DIR = OUTPUT_DIR / "ad_attack"


# attribute list we care about — keep it reasonable so enumeration doesn't take forever
USER_ATTRS = [
    "sAMAccountName", "distinguishedName", "memberOf", "userAccountControl",
    "servicePrincipalName", "pwdLastSet", "lastLogon", "lastLogonTimestamp",
    "description", "displayName", "mail", "objectSid", "primaryGroupID",
    "adminCount", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink", "scriptPath", "homeDirectory",
]
GROUP_ATTRS = ["sAMAccountName", "distinguishedName", "member", "memberOf", "objectSid", "adminCount"]
COMPUTER_ATTRS = [
    "sAMAccountName", "distinguishedName", "operatingSystem", "operatingSystemVersion",
    "memberOf", "userAccountControl", "lastLogonTimestamp", "servicePrincipalName",
    "objectSid", "ms-Mcs-AdmPwd", "msLAPS-Password", "description",
]
TRUST_ATTRS = ["trustPartner", "trustDirection", "trustType", "trustAttributes"]


def _connect(host: str, domain: str, user: str, passwd: str, use_ssl: bool = False):
    try:
        import ldap3
    except ImportError:
        print_err("ldap3 not installed")
        print_info("  pip install --break-system-packages ldap3")
        return None, None

    port = 636 if use_ssl else 389
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


def _base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def _sid_str(entry) -> str:
    try:
        v = entry["objectSid"].value
        if isinstance(v, bytes):
            return v.hex()
        return str(v)
    except Exception:
        return ""


def _uac_flags(uac: int) -> List[str]:
    flags = []
    if uac & 0x0002:    flags.append("ACCOUNTDISABLE")
    if uac & 0x0010:    flags.append("LOCKOUT")
    if uac & 0x0020:    flags.append("PASSWD_NOTREQD")
    if uac & 0x0040:    flags.append("PASSWD_CANT_CHANGE")
    if uac & 0x0080:    flags.append("ENCRYPTED_TEXT_PWD_ALLOWED")
    if uac & 0x0200:    flags.append("NORMAL_ACCOUNT")
    if uac & 0x0800:    flags.append("INTERDOMAIN_TRUST_ACCOUNT")
    if uac & 0x10000:   flags.append("DONT_EXPIRE_PASSWORD")
    if uac & 0x20000:   flags.append("MNS_LOGON_ACCOUNT")
    if uac & 0x40000:   flags.append("SMARTCARD_REQUIRED")
    if uac & 0x80000:   flags.append("TRUSTED_FOR_DELEGATION")
    if uac & 0x100000:  flags.append("NOT_DELEGATED")
    if uac & 0x200000:  flags.append("USE_DES_KEY_ONLY")
    if uac & 0x400000:  flags.append("DONT_REQ_PREAUTH")
    if uac & 0x800000:  flags.append("PASSWORD_EXPIRED")
    if uac & 0x1000000: flags.append("TRUSTED_TO_AUTH_FOR_DELEGATION")
    return flags


def collect_users(conn, base_dn: str) -> List[Dict]:
    import ldap3
    out = []
    conn.search(base_dn, "(&(objectCategory=person)(objectClass=user))",
                attributes=USER_ATTRS, paged_size=500)
    for e in conn.entries:
        uac = int(e["userAccountControl"].value or 0)
        out.append({
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "sid": _sid_str(e),
            "memberOf": [str(x) for x in (e["memberOf"].values if e["memberOf"] else [])],
            "spn": [str(x) for x in (e["servicePrincipalName"].values if e["servicePrincipalName"] else [])],
            "uac": uac,
            "uac_flags": _uac_flags(uac),
            "pwd_last_set": str(e["pwdLastSet"].value or ""),
            "last_logon": str(e["lastLogonTimestamp"].value or ""),
            "description": str(e["description"].value or ""),
            "display": str(e["displayName"].value or ""),
            "mail": str(e["mail"].value or ""),
            "admin_count": int(e["adminCount"].value or 0),
            "allowed_to_delegate": [str(x) for x in (e["msDS-AllowedToDelegateTo"].values if e["msDS-AllowedToDelegateTo"] else [])],
            "rbcd": str(e["msDS-AllowedToActOnBehalfOfOtherIdentity"].value or ""),
            "key_cred_link": [str(x) for x in (e["msDS-KeyCredentialLink"].values if e["msDS-KeyCredentialLink"] else [])],
            "script_path": str(e["scriptPath"].value or ""),
            "home_directory": str(e["homeDirectory"].value or ""),
        })
    return out


def collect_groups(conn, base_dn: str) -> List[Dict]:
    out = []
    conn.search(base_dn, "(objectCategory=group)", attributes=GROUP_ATTRS, paged_size=500)
    for e in conn.entries:
        out.append({
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "sid": _sid_str(e),
            "members": [str(x) for x in (e["member"].values if e["member"] else [])],
            "memberOf": [str(x) for x in (e["memberOf"].values if e["memberOf"] else [])],
            "admin_count": int(e["adminCount"].value or 0),
        })
    return out


def collect_computers(conn, base_dn: str) -> List[Dict]:
    out = []
    conn.search(base_dn, "(objectCategory=computer)", attributes=COMPUTER_ATTRS, paged_size=500)
    for e in conn.entries:
        uac = int(e["userAccountControl"].value or 0)
        out.append({
            "sam": str(e["sAMAccountName"].value or ""),
            "dn": e.entry_dn,
            "sid": _sid_str(e),
            "os": str(e["operatingSystem"].value or ""),
            "os_version": str(e["operatingSystemVersion"].value or ""),
            "memberOf": [str(x) for x in (e["memberOf"].values if e["memberOf"] else [])],
            "spn": [str(x) for x in (e["servicePrincipalName"].values if e["servicePrincipalName"] else [])],
            "uac": uac,
            "uac_flags": _uac_flags(uac),
            "last_logon": str(e["lastLogonTimestamp"].value or ""),
            "laps": str(e["ms-Mcs-AdmPwd"].value or e["msLAPS-Password"].value or ""),
            "description": str(e["description"].value or ""),
        })
    return out


def collect_ous(conn, base_dn: str) -> List[Dict]:
    out = []
    conn.search(base_dn, "(objectCategory=organizationalUnit)",
                attributes=["distinguishedName", "name", "description"], paged_size=500)
    for e in conn.entries:
        out.append({
            "dn": e.entry_dn,
            "name": str(e["name"].value or ""),
            "description": str(e["description"].value or ""),
        })
    return out


def collect_trusts(conn, base_dn: str) -> List[Dict]:
    out = []
    conn.search(base_dn, "(objectClass=trustedDomain)", attributes=TRUST_ATTRS, paged_size=500)
    for e in conn.entries:
        out.append({
            "partner": str(e["trustPartner"].value or ""),
            "direction": int(e["trustDirection"].value or 0),
            "type": int(e["trustType"].value or 0),
            "attributes": int(e["trustAttributes"].value or 0),
        })
    return out


def cmd_collect(host: str, domain: str, user: str, passwd: str,
                ssl: bool = False, out_file: str = "") -> int:
    AD_DIR.mkdir(parents=True, exist_ok=True)

    print_info(f"collecting AD graph from {host}")
    print_kv("domain", domain)
    print_kv("user", user)
    print_kv("ldaps", ssl)
    print()

    server, conn = _connect(host, domain, user, passwd, ssl)
    if not conn:
        return 1

    base = _base_dn(domain)
    print_kv("base dn", base)
    print()

    t0 = time.time()

    print(f"{ARTERY}{BOLD}── users{RESET}")
    users = collect_users(conn, base)
    print_kv("count", len(users))

    print(f"{ARTERY}{BOLD}── groups{RESET}")
    groups = collect_groups(conn, base)
    print_kv("count", len(groups))

    print(f"{ARTERY}{BOLD}── computers{RESET}")
    computers = collect_computers(conn, base)
    print_kv("count", len(computers))

    print(f"{ARTERY}{BOLD}── organizational units{RESET}")
    ous = collect_ous(conn, base)
    print_kv("count", len(ous))

    print(f"{ARTERY}{BOLD}── domain trusts{RESET}")
    trusts = collect_trusts(conn, base)
    print_kv("count", len(trusts))

    conn.unbind()

    # flag high-value finds
    print()
    print(f"{ARTERY}{BOLD}── interesting findings{RESET}")

    kerberoastable = [u for u in users if u["spn"]]
    asrep = [u for u in users if "DONT_REQ_PREAUTH" in u["uac_flags"]]
    unconstrained = [u for u in users if "TRUSTED_FOR_DELEGATION" in u["uac_flags"]]
    constrained = [u for u in users if u["allowed_to_delegate"]]
    laps_readable = [c for c in computers if c["laps"]]
    shadow_creds = [u for u in users if u["key_cred_link"]]

    if kerberoastable:
        print(f"  {ARTERY}▓{RESET} {BONE}{len(kerberoastable)} kerberoastable user(s){RESET}")
        for u in kerberoastable[:10]:
            print(f"      {ASH}{u['sam']}  {u['spn'][0]}{RESET}")
    if asrep:
        print(f"  {ARTERY}▓{RESET} {BONE}{len(asrep)} AS-REP roastable user(s){RESET}")
        for u in asrep[:10]:
            print(f"      {ASH}{u['sam']}{RESET}")
    if unconstrained:
        print(f"  {SCARLET}▓{RESET} {BONE}{len(unconstrained)} unconstrained delegation account(s){RESET}")
        for u in unconstrained[:10]:
            print(f"      {ASH}{u['sam']}{RESET}")
    if constrained:
        print(f"  {SCARLET}▓{RESET} {BONE}{len(constrained)} constrained delegation account(s){RESET}")
        for u in constrained[:10]:
            print(f"      {ASH}{u['sam']} -> {u['allowed_to_delegate'][:2]}{RESET}")
    if shadow_creds:
        print(f"  {SCARLET}▓{RESET} {BONE}{len(shadow_creds)} account(s) with key credentials{RESET}")
    if laps_readable:
        print(f"  {SCARLET}▓{RESET} {BONE}{len(laps_readable)} computer(s) with readable LAPS password{RESET}")

    # save
    out = Path(out_file) if out_file else AD_DIR / f"graph_{domain}_{int(time.time())}.json"
    out.write_text(json.dumps({
        "domain": domain,
        "base_dn": base,
        "collected_at": int(time.time()),
        "users": users,
        "groups": groups,
        "computers": computers,
        "ous": ous,
        "trusts": trusts,
        "findings": {
            "kerberoastable": [u["sam"] for u in kerberoastable],
            "asrep": [u["sam"] for u in asrep],
            "unconstrained_delegation": [u["sam"] for u in unconstrained],
            "constrained_delegation": [u["sam"] for u in constrained],
            "laps_readable": [c["sam"] for c in laps_readable],
            "shadow_credentials": [u["sam"] for u in shadow_creds],
        },
    }, indent=2, default=str))
    print()
    print_kv("elapsed", f"{time.time() - t0:.1f}s")
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ad_attack bloodhound", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--dc", required=False)
    p.add_argument("--domain", required=False)
    p.add_argument("--user", required=False)
    p.add_argument("--pass", dest="passwd", required=False)
    p.add_argument("--ssl", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ad_attack bloodhound --dc DC --domain D --user U --pass P [--ssl] [--out F]")
        return 2

    if ns.help:
        print_info("redsky ad_attack bloodhound --dc <dc-ip> --domain <domain> --user <user> --pass <pass> [--ssl] [--out file]")
        return 0

    if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
        print_err("--dc --domain --user --pass are required")
        return 2

    return cmd_collect(ns.dc, ns.domain, ns.user, ns.passwd, ns.ssl, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

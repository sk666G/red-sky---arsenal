# language: Python, file: Program/ad_attack/dispatch.py, target: Red Sky ad_attack router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ad_attack <sub-command> [args...]")
    print_info("")
    print_info("  bloodhound --dc DC --domain D --user U --pass P [--ssl]")
    print_info("      full LDAP graph walk — users, groups, computers, OUs, trusts")
    print_info("")
    print_info("  adcs find --dc DC --domain D --user U --pass P [--ssl]")
    print_info("  adcs request --dc DC --domain D --user U --pass P --template T --ca CA --upn alt@dom")
    print_info("      ADCS ESC1-ESC8 enumeration and certificate requests")
    print_info("")
    print_info("  delegation find --dc DC --domain D --user U --pass P")
    print_info("  delegation exploit-constrained --dc DC --domain D --user U --pass P --target HOST")
    print_info("  delegation exploit-rbcd --dc DC --domain D --user U --pass P --target HOST")
    print_info("      unconstrained / constrained / RBCD abuse")
    print_info("")
    print_info("  credentials cpassword --cpassword <b64>")
    print_info("  credentials sysvol --dc DC --domain D --user U --pass P")
    print_info("  credentials laps --dc DC --domain D --user U --pass P")
    print_info("  credentials shadow --dc DC --domain D --user U --pass P --account SAM")
    print_info("      GPP cpassword, LAPS read, shadow credentials")
    print_info("")
    print_info("  for kerberoast / asrep / dcsync / spray use: redsky creds ...")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("bloodhound", "bh"):
        from .bloodhound import run_cli as _b
        return int(_b(args[1:]))
    if sub == "adcs":
        from .adcs import run_cli as _a
        return int(_a(args[1:]))
    if sub in ("delegation", "deleg"):
        from .delegation import run_cli as _d
        return int(_d(args[1:]))
    if sub in ("credentials", "creds"):
        from .credentials import run_cli as _c
        return int(_c(args[1:]))

    print_err(f"unknown ad_attack sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

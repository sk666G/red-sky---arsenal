# language: Python, file: Program/creds/dispatch.py, target: Red Sky creds router
# Routes `redsky creds <sub>` to the right handler.

import sys
from typing import List

from Program.utils import print_info, print_err


SUB = {
    "lsass":       "lsass",
    "spray":       "spray",
    "kerberoast":  "kerberoast",
    "asrep":       "asrep",
    "dcsync":      "dcsync",
    "token":       "token",
}


def _usage():
    print_info("redsky creds <sub-command> [args...]")
    print_info("  lsass <dump.dmp>                             parse an LSASS minidump")
    print_info("  spray --target H --users a,b --pass P        password spray (smb/winrm/ldap)")
    print_info("  kerberoast --dc DC --domain D --user U --pass P")
    print_info("  asrep --dc DC --domain D --user U --pass P")
    print_info("  dcsync --dc DC --domain D --user U --pass P")
    print_info("  token <list|steal> [process]                 Windows token ops")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2

    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    target = SUB.get(sub)
    if not target:
        print_err(f"unknown creds sub-command: {sub}")
        _usage()
        return 2

    mod = __import__(f"Program.creds.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

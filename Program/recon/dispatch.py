# language: Python, file: Program/recon/dispatch.py, target: Red Sky recon router
# Routes `redsky recon <sub>` to the right sub-module.

import sys
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, RESET
from Program.utils import print_err, print_info

SUB = {
    "sweep":       "sweep",
    "arp":         "sweep",
    "scan":        "fingerprint",
    "fingerprint": "fingerprint",
    "subs":        "subs",
    "osint":       "osint",
    "leakdb":      "leakdb",
}


def _usage():
    print_info("redsky recon <sub-command> [args...]")
    print_info("  sweep <cidr|host> [threads] [tcp_port]")
    print_info("  arp")
    print_info("  fingerprint <host> [ports] [threads]")
    print_info("  subs <domain> [brute|crtsh|axfr|all]")
    print_info("  osint <username|email|domain> <target>")
    print_info("  leakdb <index|email|password|domain|stats> ...")


def cmd_update_cve():
    import subprocess, sys
    from pathlib import Path as _P
    script = _P(__file__).resolve().parent.parent.parent / "Data" / "update_cve.py"
    if not script.exists():
        print_err(f"missing: {script}")
        return 1
    return subprocess.call([sys.executable, str(script)])


def run_cli(args: List[str]) -> int:
    if args and args[0] == "update-cve":
        return cmd_update_cve()
    if not args:
        _usage()
        return 2

    sub = args[0].lower()
    target = SUB.get(sub)
    if not target:
        print_err(f"unknown recon sub-command: {sub}")
        _usage()
        return 2

    mod = __import__(f"Program.recon.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:] if target != sub else args))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

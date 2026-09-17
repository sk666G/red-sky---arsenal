# language: Python, file: Program/cctv/dispatch.py, target: Red Sky cctv router
# Routes `redsky cctv <sub>` to the right handler.

import sys
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, RESET
from Program.utils import print_err, print_info


SUB = {
    "discover": "discover",
    "creds":    "default_creds",
    "stream":   "stream",
    "kill":     "kill",
}


def _usage():
    print_info("redsky cctv <sub-command> [args...]")
    print_info("  discover <cidr|ip> [threads]")
    print_info("  creds    <cidr|ip> [threads]")
    print_info("  stream   <probe|view|capture> <rtsp_url> [secs]")
    print_info("  kill     <ip> <vendor> <user> <pass> <action> [secs]")
    print_info("           action: teardown | disable | lockout")


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
        print_err(f"unknown cctv sub-command: {sub}")
        _usage()
        return 2

    mod = __import__(f"Program.cctv.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

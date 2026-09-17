# language: Python, file: Program/c2/dispatch.py, target: Red Sky c2 router
import sys
from typing import List
from Program.utils import print_info, print_err

SUB = {
    "serve":     "listener",
    "listener":  "listener",
    "stats":     "listener",
    "bots":      "listener",
    "channels":  "channels",
    "malleable": "malleable",
    "profile":   "malleable",
}


def _usage():
    print_info("redsky c2 <sub-command> [args...]")
    print_info("  serve [--host H] [--port N] [--tls]     start C2 listener")
    print_info("  stats                                    fleet stats")
    print_info("  bots                                     list bots")
    print_info("  channels <list|show NAME>                alternate channels")
    print_info("  malleable <list|show NAME|export>        HTTP profiles")


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
        print_err(f"unknown c2 sub-command: {sub}")
        _usage()
        return 2
    mod = __import__(f"Program.c2.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

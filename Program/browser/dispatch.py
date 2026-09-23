# language: Python, file: Program/browser/dispatch.py, target: Red Sky browser router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky browser <sub-command> [args...]")
    print_info("")
    print_info("  extensions <chromium|firefox|launch|verify> [opts]")
    print_info("      malicious browser extension generator + launcher")
    print_info("")
    print_info("  cssexfil <attr|has|font|react|page|parse> [opts]")
    print_info("      CSS-only data exfiltration payloads")
    print_info("")
    print_info("  history <profiles|history|cookies|logins|key> [opts]")
    print_info("      local browser profile scraping (Chromium, Firefox, Safari)")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("extensions", "ext", "e"):
        from .extensions import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("cssexfil", "css", "c"):
        from .cssexfil import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("history", "hist", "h"):
        from .history import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown browser sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

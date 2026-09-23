# language: Python, file: Program/mobile/dispatch.py, target: Red Sky mobile router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky mobile <sub-command> [args...]")
    print_info("")
    print_info("  apk <info|decode|inject|build|tools> <apk-or-dir>")
    print_info("      teardown an APK, inject a smali beacon, repack + resign")
    print_info("")
    print_info("  ios <rootcert|webclip|mdm|wifi|proxy|combo> [opts]")
    print_info("      build a .mobileconfig profile (cert trust, web clip, MDM enroll)")
    print_info("")
    print_info("  frida <list|gen|attach|devices|ps> [target] [--hook NAME]")
    print_info("      generate + run Frida hooks (ssl unpin, root bypass, crypto dump)")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("apk", "android", "a"):
        from .apk import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("ios", "iphone", "i"):
        from .ios import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("frida", "hook", "f"):
        from .frida import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown mobile sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

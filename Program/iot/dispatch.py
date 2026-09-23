# language: Python, file: Program/iot/dispatch.py, target: Red Sky iot router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky iot <sub-command> [args...]")
    print_info("")
    print_info("  discover [scan <cidr>|list]")
    print_info("      ARP + mDNS + SSDP + MQTT + CoAP discovery across the LAN")
    print_info("")
    print_info("  defaults <list|export|spray> [--vendor X] [--proto http]")
    print_info("      default credential catalog + rate-limited spray")
    print_info("")
    print_info("  mqtt <connect|subscribe|topics|publish|acl> <host> [--topic #]")
    print_info("      broker probe, subscribe-all, topic enumeration, ACL probing")
    print_info("")
    print_info("  firmware <list|unpack|secrets> [target]")
    print_info("      binwalk + ubi/squashfs extraction + secret hunting")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("discover", "scan", "d"):
        from .discover import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("defaults", "creds", "c"):
        from .defaults import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("mqtt", "broker", "m"):
        from .mqtt import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("firmware", "fw", "f"):
        from .firmware import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown iot sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

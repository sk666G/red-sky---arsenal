# language: Python, file: Program/geoip/dispatch.py, target: Red Sky geoip router
import sys
from typing import List
from Program.utils import print_info, print_err


SUB = {
    "lookup": "lookup",
    "ip": "lookup",
    "leak": "leak",
    "app": "leak",
    "webrtc": "webrtc",
    "rtc": "webrtc",
}


def _usage():
    print_info("redsky geoip <sub-command> [args...]")
    print_info("  lookup <ip> [--all]        multi-source IP geolocation")
    print_info("  leak <app|all>             CDN edge + region signal from app hosts")
    print_info("  webrtc <serve|hits>        WebRTC public-IP harvest")
    print_info("  apps                       list known apps for leak")


def cmd_apps():
    from .leak import APPS
    print_info(f"{len(APPS)} apps known")
    print()
    for k in sorted(APPS):
        print(f"  {k}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub == "apps":
        return cmd_apps()
    target = SUB.get(sub)
    if not target:
        print_err(f"unknown geoip sub-command: {sub}")
        _usage()
        return 2
    mod = __import__(f"Program.geoip.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

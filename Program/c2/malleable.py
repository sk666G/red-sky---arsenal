# language: Python, file: Program/c2/malleable.py, target: Red Sky c2 - malleable profiles

import json
import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR


PROFILES_DIR = DATA_DIR / "profiles"


DEFAULT_PROFILES = {
    "default": {
        "description": "generic HTTPS beacon",
        "beacon_uris": ["/api/beacon"],
        "result_uris": ["/api/result"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        },
    },
    "cloudflare-cdn": {
        "description": "blends as a Cloudflare CDN request",
        "beacon_uris": ["/cdn-cgi/trace", "/cdn-cgi/beacon"],
        "result_uris": ["/cdn-cgi/result"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
        },
    },
    "office365": {
        "description": "looks like Microsoft 365 API traffic",
        "beacon_uris": ["/common/oauth2/v2.0/token", "/common/discovery/instance"],
        "result_uris": ["/common/oauth2/v2.0/result"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "headers": {"Accept": "application/json"},
    },
    "slack-webhook": {
        "description": "looks like Slack webhook traffic",
        "beacon_uris": ["/api/chat.postMessage"],
        "result_uris": ["/api/files.upload"],
        "ua": "Slackbot 1.0 (+https://api.slack.com/robots)",
        "headers": {"Accept": "application/json", "Content-Type": "application/json; charset=utf-8"},
    },
}


def cmd_list() -> int:
    print_info(f"{len(DEFAULT_PROFILES)} built-in malleable profiles")
    print()
    for name, p in DEFAULT_PROFILES.items():
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<20}{RESET} {ASH}{p['description']}{RESET}")
        print(f"      {CLOT}beacon: {', '.join(p['beacon_uris'])}{RESET}")
    return 0


def cmd_show(name: str) -> int:
    if name not in DEFAULT_PROFILES:
        print_err(f"unknown profile: {name}")
        return 2
    print(json.dumps(DEFAULT_PROFILES[name], indent=2))
    return 0


def cmd_export(name: str = "", out_dir: str = "") -> int:
    d = Path(out_dir) if out_dir else PROFILES_DIR
    d.mkdir(parents=True, exist_ok=True)
    profiles = {name: DEFAULT_PROFILES[name]} if name in DEFAULT_PROFILES else DEFAULT_PROFILES
    for pname, pdata in profiles.items():
        out = d / f"{pname}.json"
        out.write_text(json.dumps(pdata, indent=2))
        print_ok(f"{out}")
    print()
    print_info("activate a profile: set c2.profile in Data/config.json")
    return 0


def run_cli(args: List[str]) -> int:
    if not args or args[0] == "list":
        return cmd_list()
    sub = args[0]
    if sub == "show" and len(args) > 1:
        return cmd_show(args[1])
    if sub == "export":
        return cmd_export(args[1] if len(args) > 1 else "",
                         args[2] if len(args) > 2 else "")
    print_err(f"unknown malleable action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

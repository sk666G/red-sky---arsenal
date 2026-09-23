# language: Python, file: Program/social/profile.py, target: Red Sky social — target dossier
# Aggregates the JSON outputs produced by osint.py into a single dossier.
# Input: a directory of osint_*.json files, or run with --auto to invoke the
# osint subcommands first (requires network). Merges usernames, emails, phones,
# domains, and constructs name-variant candidates from what it finds.

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"
DOSSIER_DIR = SOCIAL_DIR / "dossiers"
DOSSIER_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(p: Path) -> Dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def cmd_build(input_dir: str, name: str, out_file: str) -> int:
    root = Path(input_dir).expanduser() if input_dir else SOCIAL_DIR
    if not root.exists():
        print_err("input dir not found: " + str(root))
        return 1

    print_info("building dossier from " + str(root))
    print()

    dossier: Dict = {
        "name": name or "unknown",
        "created": time.time(),
        "usernames": set(),
        "emails": set(),
        "phones": set(),
        "domains": set(),
        "platforms": {},
        "sources": [],
    }

    for p in root.rglob("*.json"):
        if p.parent.name == "dossiers":
            continue
        data = _load_json(p)
        if not data:
            continue
        dossier["sources"].append(str(p.relative_to(root)))

        # usernames
        if "username" in data:
            dossier["usernames"].add(data["username"])
            for hit in data.get("found", []):
                platform = hit.get("platform")
                if platform:
                    dossier["platforms"].setdefault(platform, []).append(hit.get("url", ""))

        # email
        if "email" in data:
            dossier["emails"].add(data["email"])
            if data.get("domain"):
                dossier["domains"].add(data["domain"])

        # phone
        if "digits" in data:
            dossier["phones"].add(data["digits"])

        # domain
        if "domain" in data:
            dossier["domains"].add(data["domain"])
            for e in data.get("emails", []):
                dossier["emails"].add(e)

    # name variants — if we have an email like firstname.lastname@x, expand
    variants = set()
    for email in dossier["emails"]:
        local = email.split("@")[0]
        if "." in local or "_" in local or "-" in local:
            for sep in (".", "_", "-"):
                if sep in local:
                    parts = local.split(sep)
                    if len(parts) >= 2:
                        variants.add(" ".join(parts))
                        variants.add(parts[0].capitalize() + " " + parts[-1].capitalize())
                        variants.add(parts[0] + parts[-1])
                        variants.add(parts[0][0] + parts[-1])
                        variants.add(parts[0] + parts[-1][0])

    dossier["name_variants"] = sorted(variants)
    dossier["usernames"] = sorted(dossier["usernames"])
    dossier["emails"] = sorted(dossier["emails"])
    dossier["phones"] = sorted(dossier["phones"])
    dossier["domains"] = sorted(dossier["domains"])

    # pretty print
    print_info("dossier: " + dossier["name"])
    print()
    for k in ("usernames", "emails", "phones", "domains", "name_variants"):
        v = dossier.get(k, [])
        if not v:
            continue
        print(ARTERY + BOLD + "-- " + k + " (" + str(len(v)) + ")" + RESET)
        for item in v[:30]:
            print("  " + SCARLET + "*" + RESET + " " + BONE + str(item) + RESET)
        if len(v) > 30:
            print("  " + ASH + "... +" + str(len(v) - 30) + " more" + RESET)
        print()

    if dossier["platforms"]:
        print(ARTERY + BOLD + "-- platforms" + RESET)
        for platform, urls in sorted(dossier["platforms"].items()):
            print("  " + SCARLET + "*" + RESET + " " + BONE + platform.ljust(18) + RESET
                  + " " + ASH + str(len(urls)) + " URL(s)" + RESET)
        print()

    out = Path(out_file) if out_file else DOSSIER_DIR / ("dossier_" + (name or "target") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(dossier, indent=2, default=str))
    print_kv("saved", out)
    return 0


def cmd_show(dossier_file: str) -> int:
    p = Path(dossier_file).expanduser()
    if not p.exists():
        print_err("dossier not found: " + str(p))
        return 1
    d = _load_json(p)
    if not d:
        print_err("bad dossier")
        return 1

    print_info("dossier: " + d.get("name", "unknown"))
    print_kv("created", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.get("created", 0))))
    print_kv("sources", str(len(d.get("sources", []))))
    print()
    for k in ("usernames", "emails", "phones", "domains", "name_variants"):
        v = d.get(k, [])
        if v:
            print(ARTERY + BOLD + "-- " + k + RESET)
            for item in v:
                print("  " + SCARLET + "*" + RESET + " " + BONE + str(item) + RESET)
            print()
    return 0


def cmd_list() -> int:
    dossiers = sorted(DOSSIER_DIR.glob("*.json"))
    if not dossiers:
        print_info("no dossiers yet")
        return 0
    print_info(str(len(dossiers)) + " dossier(s)")
    print()
    for d in dossiers:
        try:
            data = json.loads(d.read_text())
            n = data.get("name", "?")
            print("  " + BONE + d.name + RESET + "  " + ARTERY + n + RESET)
        except Exception:
            print("  " + BONE + d.name + RESET)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky social profile", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["build", "show", "list", "help"])
    p.add_argument("--in", dest="indir", default="")
    p.add_argument("--dossier", default="")
    p.add_argument("--name", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky social profile <build|show|list> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("build [--in dir] [--name target]   -- merge osint_*.json into a dossier")
        print_info("show --dossier file.json            -- print a saved dossier")
        print_info("list                                -- list all dossiers")
        return 0

    if ns.action == "build":
        return cmd_build(ns.indir, ns.name, ns.out)
    if ns.action == "show":
        if not ns.dossier:
            print_err("--dossier required")
            return 2
        return cmd_show(ns.dossier)
    if ns.action == "list":
        return cmd_list()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

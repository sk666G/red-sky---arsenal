# language: Python, file: Program/supply_chain/confusion.py, target: Red Sky supply_chain — dependency confusion
# Detects whether a package name that appears in a target's manifests is
# publicly claimable on npm / PyPI / etc. If yes, an attacker can register the
# same name publicly and the target's build system will pull the attacker copy.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SC_DIR = OUTPUT_DIR / "supply_chain"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


def _npm_exists(name: str) -> bool:
    url = f"https://registry.npmjs.org/{name}"
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": UA})
        return r.status_code == 200
    except requests.RequestException:
        return False


def _pypi_exists(name: str) -> bool:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": UA})
        return r.status_code == 200
    except requests.RequestException:
        return False


def _gem_exists(name: str) -> bool:
    url = f"https://rubygems.org/api/v1/gems/{name}.json"
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": UA})
        return r.status_code == 200
    except requests.RequestException:
        return False


def _cargo_exists(name: str) -> bool:
    url = f"https://crates.io/api/v1/crates/{name}"
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": UA})
        return r.status_code == 200
    except requests.RequestException:
        return False


REGISTRIES = {
    "npm":   _npm_exists,
    "pypi":  _pypi_exists,
    "gem":   _gem_exists,
    "cargo": _cargo_exists,
}


def check_name(name: str, registry: str) -> Dict:
    fn = REGISTRIES.get(registry)
    if not fn:
        return {"name": name, "registry": registry, "error": "unknown registry"}
    exists = fn(name)
    return {
        "name": name,
        "registry": registry,
        "exists_publicly": exists,
        "claimable": not exists,
    }


def cmd_check(names: List[str], registry: str, out_file: str = "") -> int:
    SC_DIR.mkdir(parents=True, exist_ok=True)
    print_info(f"checking {len(names)} name(s) against {registry}")
    print()

    results = []
    t0 = time.time()

    for name in names:
        r = check_name(name, registry)
        results.append(r)
        if r.get("claimable"):
            print(f"  {SCARLET}*{RESET} {BONE}{name:<40}{RESET} {SCARLET}CLAIMABLE — attacker can register{RESET}")
        elif r.get("exists_publicly"):
            print(f"  {ASH}*{RESET} {BONE}{name:<40}{RESET} {ASH}already exists publicly{RESET}")

    print()
    print_kv("elapsed", f"{time.time()-t0:.1f}s")
    print_kv("claimable", sum(1 for r in results if r.get("claimable")))

    out = Path(out_file) if out_file else SC_DIR / f"confusion_{registry}_{int(time.time())}.json"
    out.write_text(json.dumps(results, indent=2))
    print_kv("saved", out)
    return 0


def cmd_from_manifest(path: str, registry: str, out_file: str = "") -> int:
    """Extract package names from a manifest file and check each one."""
    p = Path(path).expanduser()
    if not p.exists():
        print_err(f"file not found: {p}")
        return 1

    names = _extract_names(p, registry)
    if not names:
        print_warn(f"no package names found in {p.name}")
        return 1

    return cmd_check(names, registry, out_file)


def _extract_names(p: Path, registry: str) -> List[str]:
    text = p.read_text(encoding="utf-8", errors="replace")
    names = []

    if registry == "npm" or p.name in ("package.json",):
        try:
            data = json.loads(text)
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                for k in (data.get(section) or {}):
                    names.append(k)
        except json.JSONDecodeError:
            pass
    elif registry == "pypi":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # strip version specifiers, extras
            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "[", ";"):
                if sep in line:
                    line = line.split(sep, 1)[0].strip()
            if line:
                names.append(line)
    elif registry == "gem":
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("gem "):
                # gem "name", "~> x.y"
                try:
                    name = line.split("\"")[1] if "\"" in line else line.split("'")[1]
                    names.append(name)
                except IndexError:
                    continue
    elif registry == "cargo":
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and "]" in line:
                continue
            if "=" in line and not line.startswith("#"):
                name = line.split("=", 1)[0].strip()
                if name and not name.startswith("["):
                    names.append(name)

    return sorted(set(n for n in names if n))


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky supply_chain confusion", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="check")
    p.add_argument("--registry", default="npm", choices=["npm", "pypi", "gem", "cargo"])
    p.add_argument("--names", nargs="*", default=[])
    p.add_argument("--manifest", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky supply_chain confusion <check|manifest> --registry npm --names pkg1 pkg2")
        return 2

    if ns.help:
        print_info("redsky supply_chain confusion check --registry npm --names internal-pkg1 internal-pkg2")
        print_info("redsky supply_chain confusion manifest --registry npm --manifest package.json")
        print_info("  reports which names are NOT registered publicly -> register them yourself")
        return 0

    if ns.action == "check":
        if not ns.names:
            print_err("--names needed (space-separated list)")
            return 2
        return cmd_check(ns.names, ns.registry, ns.out)
    if ns.action == "manifest":
        if not ns.manifest:
            print_err("--manifest needed")
            return 2
        return cmd_from_manifest(ns.manifest, ns.registry, ns.out)

    print_err(f"unknown confusion action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

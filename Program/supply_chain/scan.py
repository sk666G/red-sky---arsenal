# language: Python, file: Program/supply_chain/scan.py, target: Red Sky supply_chain — manifest leak scanner
# Scans a GitHub org's public repos for package names referenced in manifests.
# The ones that are NOT registered publicly are dependency-confusion candidates.

import base64
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SC_DIR = OUTPUT_DIR / "supply_chain"
GH_API = "https://api.github.com"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

MANIFEST_NAMES = {
    "package.json":  "npm",
    "package-lock.json": "npm",
    "requirements.txt": "pypi",
    "Pipfile":       "pypi",
    "pyproject.toml": "pypi",
    "setup.py":      "pypi",
    "Gemfile":       "gem",
    "Gemfile.lock":  "gem",
    "Cargo.toml":    "cargo",
    "Cargo.lock":    "cargo",
    "go.mod":        "go",
}


def _gh_get(url, token=""):
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return requests.get(url, headers=headers, timeout=15)


def list_org_repos(org, token="", max_repos=100):
    repos = []
    page = 1
    while len(repos) < max_repos:
        url = GH_API + "/orgs/" + org + "/repos?per_page=100&page=" + str(page)
        r = _gh_get(url, token)
        if r.status_code == 404:
            url = GH_API + "/users/" + org + "/repos?per_page=100&page=" + str(page)
            r = _gh_get(url, token)
        if r.status_code != 200:
            break
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos[:max_repos]


def list_repo_tree(owner, repo, token=""):
    url = GH_API + "/repos/" + owner + "/" + repo + "/git/trees/HEAD?recursive=1"
    r = _gh_get(url, token)
    if r.status_code != 200:
        return []
    return r.json().get("tree", [])


def fetch_file(owner, repo, path, token=""):
    url = GH_API + "/repos/" + owner + "/" + repo + "/contents/" + path
    r = _gh_get(url, token)
    if r.status_code != 200:
        return ""
    data = r.json()
    if data.get("encoding") == "base64":
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return data.get("content", "")


def parse_npm(text):
    names = set()
    try:
        data = json.loads(text)
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for k in (data.get(section) or {}):
                names.add(k)
    except json.JSONDecodeError:
        pass
    return names


def parse_pypi(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "[", ";", " "):
            if sep in line:
                line = line.split(sep, 1)[0].strip()
        if line and re.match(r"^[A-Za-z0-9_.\-]+$", line):
            names.add(line)
    return names


def parse_gem(text):
    names = set()
    for line in text.splitlines():
        m = re.search(r"gem\s+['\"]([^'\"]+)['\"]", line)
        if m:
            names.add(m.group(1))
    return names


def parse_cargo(text):
    names = set()
    in_deps = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and "dependencies" in line:
            in_deps = True
            continue
        if line.startswith("[") and "dependencies" not in line:
            in_deps = False
            continue
        if in_deps and "=" in line:
            name = line.split("=", 1)[0].strip()
            if name and re.match(r"^[A-Za-z0-9_\-]+$", name):
                names.add(name)
    return names


def parse_go(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ") or (line and not line.startswith("//") and "/" in line and " " in line):
            parts = line.split()
            if parts:
                pkg = parts[0] if parts[0] != "require" else (parts[1] if len(parts) > 1 else "")
                if "/" in pkg:
                    names.add(pkg)
    return names


PARSERS = {
    "npm":   parse_npm,
    "pypi":  parse_pypi,
    "gem":   parse_gem,
    "cargo": parse_cargo,
    "go":    parse_go,
}


def scan_repo(owner, repo, token=""):
    findings = []
    tree = list_repo_tree(owner, repo, token)
    for entry in tree:
        path = entry.get("path", "")
        fname = Path(path).name
        registry = MANIFEST_NAMES.get(fname)
        if not registry:
            continue
        text = fetch_file(owner, repo, path, token)
        if not text:
            continue
        parser = PARSERS.get(registry)
        if not parser:
            continue
        for name in parser(text):
            findings.append({
                "repo": owner + "/" + repo,
                "manifest": path,
                "registry": registry,
                "name": name,
            })
    return findings


def cmd_scan(org, token="", out_file=""):
    SC_DIR.mkdir(parents=True, exist_ok=True)
    print_info("scanning public repos under '" + org + "' for manifest leaks")
    print()

    repos = list_org_repos(org, token)
    if not repos:
        print_err("no repos found for '" + org + "' (private org? bad name? rate limit?)")
        return 1

    print_kv("repos", len(repos))
    print()

    all_findings = []
    t0 = time.time()
    for i, r in enumerate(repos, 1):
        name = r.get("name", "")
        print("  " + ASH + "[" + str(i) + "/" + str(len(repos)) + "]" + RESET + " " + BONE + org + "/" + name + RESET, end="\r")
        found = scan_repo(org, name, token)
        if found:
            print("  " + SCARLET + "*" + RESET + " " + BONE + org + "/" + name + RESET + " " + SCARLET + str(len(found)) + " package refs" + RESET + "        ")
        all_findings.extend(found)

    print()
    print_kv("elapsed", str(round(time.time() - t0, 1)) + "s")
    print_kv("total refs", len(all_findings))

    uniq = {}
    for f in all_findings:
        uniq.setdefault(f["registry"], set()).add(f["name"])

    print()
    for reg, names in uniq.items():
        print(ARTERY + BOLD + "-- " + reg + " (" + str(len(names)) + " unique)" + RESET)
        for n in sorted(names)[:30]:
            print("  " + ARTERY + "*" + RESET + " " + BONE + n + RESET)
        if len(names) > 30:
            print("  " + ASH + "... +" + str(len(names) - 30) + " more" + RESET)
        print()

    out = Path(out_file) if out_file else SC_DIR / ("scan_" + org + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"org": org, "repos": len(repos), "findings": all_findings}, indent=2))
    print_kv("saved", out)
    print()
    print_info("next: pipe the unique names into confusion check")
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky supply_chain scan", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("org", nargs="?", default="")
    p.add_argument("--token", default="", help="GitHub token for higher rate limit / private repos")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky supply_chain scan <github-org-or-user> [--token GH_TOKEN]")
        return 2

    if ns.help:
        print_info("redsky supply_chain scan mycompany --token ghp_xxx")
        return 0

    if not ns.org:
        print_err("provide a GitHub org or username")
        return 2

    return cmd_scan(ns.org, ns.token, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/social/profile.py, target: Red Sky social — target dossier
# Aggregates the JSON outputs from Program/social/osint.py into a target
# dossier. Reads every hit file under Output/social/, groups by target,
# emits a markdown report with:
#
#   - Executive summary (who we found, key handles)
#   - Platform presence map
#   - Emails / phones / domains
#   - Attack-surface notes (SSO patterns, dev environments, password hints
#     derived from username variants)
#   - Suggested next collection steps

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"
PROFILE_DIR = SOCIAL_DIR / "profiles"


def _load_json(p: Path) -> Optional[object]:
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _classify(path: Path) -> str:
    n = path.name
    if n.startswith("username_"):
        return "username"
    if n.startswith("email_"):
        return "email"
    if n.startswith("domain_"):
        return "domain"
    return "other"


def _extract_target_from_name(p: Path) -> str:
    """username_<handle>_<ts>.json → <handle>"""
    stem = p.stem
    parts = stem.split("_")
    if len(parts) >= 3 and parts[-1].isdigit():
        return "_".join(parts[1:-1])
    return "_".join(parts[1:]) if len(parts) > 1 else stem


def _password_variants(handle: str, real_name: str = "") -> List[str]:
    """Generate the pattern of passwords a target is likely to use —
    documents for the operator to feed into a spray, not a lookup."""
    base_words: Set[str] = set()
    if handle:
        base_words.add(handle.lower())
        base_words.add(handle)
    if real_name:
        for part in re.split(r"[^A-Za-z]+", real_name):
            if part:
                base_words.add(part.lower())
                base_words.add(part)

    years = [str(y) for y in range(1980, 2030)]
    suffixes = ["!", "1", "123", "2024", "2025", "!", "@"]
    prefixes = [""]

    out = set()
    for w in base_words:
        for y in years[::5]:  # sample — every 5th year keeps this small
            out.add(w + y)
            out.add(w.capitalize() + y)
        for s in suffixes:
            out.add(w + s)
        out.add(w.capitalize() + "123")
        out.add(w + "!")
    return sorted(out)[:80]


def _collect_all(root: Path) -> Dict:
    """Walk Output/social/*.json, bucket by classification."""
    buckets: Dict[str, List[Dict]] = {"username": [], "email": [], "domain": [], "other": []}
    targets: Set[str] = set()
    for f in root.glob("*.json"):
        kind = _classify(f)
        data = _load_json(f)
        if data is None:
            continue
        entry = {"file": str(f), "data": data}
        buckets[kind].append(entry)
        if kind == "username":
            t = _extract_target_from_name(f)
            if t:
                targets.add(t)
    return {"buckets": buckets, "targets": sorted(targets)}


def _render_markdown(target: str, collected: Dict, extra: Dict) -> str:
    lines: List[str] = []
    lines.append("# Target dossier — " + target)
    lines.append("")
    lines.append("_Generated " + time.strftime("%Y-%m-%d %H:%M:%S") + "_")
    lines.append("")

    # ── summary ──
    lines.append("## Summary")
    lines.append("")
    handles = collected.get("handles", [])
    emails = collected.get("emails", [])
    domains = collected.get("domains", [])
    lines.append("- Handles: **" + str(len(handles)) + "**")
    if handles:
        for h in handles[:10]:
            lines.append("  - " + h)
    lines.append("- Emails: **" + str(len(emails)) + "**")
    for e in emails[:10]:
        lines.append("  - " + e)
    lines.append("- Domains: **" + str(len(domains)) + "**")
    for d in domains[:10]:
        lines.append("  - " + d)
    lines.append("")

    # ── platform presence ──
    lines.append("## Platform presence")
    lines.append("")
    if collected.get("platforms"):
        for p in sorted(collected["platforms"]):
            lines.append("- **" + p["platform"] + "** — " + p.get("url", ""))
    else:
        lines.append("_No platform hits collected._")
    lines.append("")

    # ── domain footprint ──
    lines.append("## Domain footprint")
    lines.append("")
    if collected.get("subdomains"):
        for s in collected["subdomains"]:
            lines.append("- `" + s["host"] + "` → " + s["ip"])
    else:
        lines.append("_No subdomains collected._")
    lines.append("")

    # ── derived attack surface ──
    lines.append("## Derived attack surface")
    lines.append("")
    if collected.get("subdomains"):
        # look for interesting ones
        interesting = []
        for s in collected["subdomains"]:
            h = s["host"].lower()
            for kw in ("admin", "dev", "staging", "internal", "intranet", "git", "jenkins", "jira", "grafana", "db"):
                if kw in h:
                    interesting.append(s["host"] + " (keyword: " + kw + ")")
                    break
        if interesting:
            lines.append("### High-interest subdomains")
            for i in interesting:
                lines.append("- " + i)
            lines.append("")

    if target:
        variants = _password_variants(target)
        if variants:
            lines.append("### Suggested password spray candidates")
            lines.append("")
            lines.append("_Derived from the handle — common username+year/suffix patterns._")
            lines.append("")
            lines.append("```")
            for v in variants[:50]:
                lines.append(v)
            lines.append("```")
            lines.append("")

    lines.append("## Suggested next steps")
    lines.append("")
    if not collected.get("platforms"):
        lines.append("- Run `redsky social osint username --user " + target + "`")
    if not collected.get("subdomains"):
        lines.append("- If a domain is known, run `redsky social osint domain --domain <domain>`")
    if not collected.get("emails"):
        lines.append("- If a domain is known, derive email pattern and run `redsky social osint email`")
    lines.append("- Feed discovered subdomains into `redsky iot` / `redsky scanner` modules")
    lines.append("- Feed discovered emails into `redsky phish` for pretext generation")
    lines.append("")
    return "\n".join(lines)


def cmd_build(target: str, extra_domains: str, out: str) -> int:
    SOCIAL_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    print_info("target profile builder")
    print_kv("target", target or "(all)")
    print_kv("source", SOCIAL_DIR)
    print()

    collected = _collect_all(SOCIAL_DIR)
    # explicit target — restrict to files whose name contains it
    if target:
        for kind in list(collected["buckets"].keys()):
            collected["buckets"][kind] = [
                e for e in collected["buckets"][kind]
                if target.lower() in e["file"].lower()
            ]

    platforms = []
    for e in collected["buckets"]["username"]:
        for hit in (e["data"] if isinstance(e["data"], list) else []):
            if isinstance(hit, dict):
                platforms.append(hit)

    subdomains = []
    for e in collected["buckets"]["domain"]:
        for hit in (e["data"] if isinstance(e["data"], list) else []):
            if isinstance(hit, dict):
                subdomains.append(hit)

    emails = []
    for e in collected["buckets"]["email"]:
        if isinstance(e["data"], dict) and e["data"].get("email"):
            emails.append(e["data"]["email"])

    domains = list({s["host"].split(".", 1)[-1] for s in subdomains if "host" in s})
    if extra_domains:
        for d in extra_domains.split(","):
            d = d.strip()
            if d:
                domains.append(d)
    handles = [target] if target else []

    agg = {
        "platforms": platforms,
        "subdomains": subdomains,
        "emails": emails,
        "domains": sorted(set(domains)),
        "handles": handles,
    }

    md = _render_markdown(target or "unknown", agg, {})
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = Path(out) if out else PROFILE_DIR / ("profile_" + (target or "all") + "_" + ts + ".md")
    out_path.write_text(md)

    print_kv("platforms", len(platforms))
    print_kv("subdomains", len(subdomains))
    print_kv("emails", len(emails))
    print_kv("domains", len(agg["domains"]))
    print()
    print_ok("dossier written: " + str(out_path))
    print()
    print(md[:2000])
    if len(md) > 2000:
        print()
        print_info("... full report at " + str(out_path))
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky social profile <sub-command>")
        print_info("")
        print_info("  build [--target HANDLE] [--extra-domains a.com,b.com] [--out FILE]")
        print_info("      aggregate osint JSON into a markdown dossier")
        return 0

    if sub == "build":
        p = argparse.ArgumentParser(prog="redsky social profile build", add_help=False)
        p.add_argument("--target", default="")
        p.add_argument("--extra-domains", default="")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social profile build [--target HANDLE] [--out FILE]")
            return 2
        return cmd_build(ns.target, ns.extra_domains, ns.out)

    print_err("unknown profile sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

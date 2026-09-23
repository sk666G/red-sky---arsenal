# language: Python, file: Program/report/findings.py, target: Red Sky report — finding collector
# Aggregates JSON findings from Output/findings/*.json into a normalized set.
# Subcommands:
#   add     -- create a new finding from CLI args
#   import  -- read JSON from stdin or a file (one finding or a list)
#   list    -- list findings with optional filter
#   stats   -- counts by severity / module / target
#   score   -- overall risk score (weighted severity + exploitability)
#   dedupe  -- collapse identical findings (same title+target+evidence hash)
# Finding schema:
#   {id, module, target, title, severity, cvss, evidence[], remediation,
#    references[], cwe, created, tags[]}

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


REPORT_DIR = OUTPUT_DIR / "report"
FINDINGS_DIR = OUTPUT_DIR / "findings"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
FINDINGS_DIR.mkdir(parents=True, exist_ok=True)


SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {
    "info":     0.1,
    "low":      1.0,
    "medium":   3.0,
    "high":     7.0,
    "critical": 10.0,
}
SEVERITY_COLOR = {
    "info":     ASH,
    "low":      ASH,
    "medium":   ARTERY,
    "high":     SCARLET,
    "critical": SCARLET + BOLD,
}


def _new_id() -> str:
    return "F-" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:10].upper()


def _normalize(f: Dict) -> Dict:
    """Ensure a finding has all required fields with sane defaults."""
    out = {
        "id":           f.get("id") or _new_id(),
        "module":       f.get("module", "manual"),
        "target":       f.get("target", ""),
        "title":        f.get("title", "untitled"),
        "severity":     f.get("severity", "medium").lower(),
        "cvss":         float(f.get("cvss", 0.0) or 0.0),
        "evidence":     f.get("evidence") or [],
        "remediation":  f.get("remediation", ""),
        "references":   f.get("references") or [],
        "cwe":          f.get("cwe", ""),
        "tags":         f.get("tags") or [],
        "created":      f.get("created", time.time()),
    }
    if out["severity"] not in SEVERITY_LEVELS:
        out["severity"] = "medium"
    if not isinstance(out["evidence"], list):
        out["evidence"] = [str(out["evidence"])]
    return out


def _finding_path(f: Dict) -> Path:
    return FINDINGS_DIR / (f["id"] + ".json")


def _save(f: Dict) -> Path:
    p = _finding_path(f)
    p.write_text(json.dumps(f, indent=2))
    return p


def _load_all() -> List[Dict]:
    out = []
    for p in sorted(FINDINGS_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text())
            if isinstance(d, list):
                out += [_normalize(x) for x in d]
            else:
                out.append(_normalize(d))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def _render(f: Dict) -> str:
    col = SEVERITY_COLOR.get(f["severity"], ASH)
    line = (col + f["severity"].upper().ljust(9) + RESET
            + BONE + f["id"].ljust(14) + RESET
            + ARTERY + (f["module"] or "").ljust(16) + RESET
            + CLOT + (f["title"] or "")[:60] + RESET)
    if f["target"]:
        line += "  " + ASH + f["target"][:40] + RESET
    return line


# ── add ──
def cmd_add(module: str, target: str, title: str, severity: str,
            cvss: float, remediation: str, evidence: List[str],
            cwe: str, tags: List[str], out_file: str) -> int:
    if not title:
        print_err("--title required")
        return 2
    f = _normalize({
        "module": module, "target": target, "title": title,
        "severity": severity, "cvss": cvss, "remediation": remediation,
        "evidence": evidence, "cwe": cwe, "tags": tags,
    })
    p = _save(f)
    print_ok("finding added")
    print_kv("id", f["id"])
    print_kv("severity", f["severity"])
    print_kv("path", p)
    return 0


# ── import ──
def cmd_import(src: str) -> int:
    """Import from a file or stdin. Accepts a single dict or a list of dicts."""
    if src == "-" or not src:
        text = sys.stdin.read()
    else:
        p = Path(src).expanduser()
        if not p.exists():
            print_err("file not found: " + str(p))
            return 1
        text = p.read_text()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print_err("bad JSON: " + str(e))
        return 1

    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        print_err("expected object or array")
        return 1

    for item in items:
        f = _normalize(item)
        _save(f)
    print_ok(str(len(items)) + " finding(s) imported")
    return 0


# ── list ──
def cmd_list(severity: str, module: str, target: str, tag: str,
             out_file: str) -> int:
    all_f = _load_all()
    shown = all_f
    if severity:
        shown = [f for f in shown if f["severity"] == severity]
    if module:
        shown = [f for f in shown if f["module"] == module]
    if target:
        shown = [f for f in shown if target in f["target"]]
    if tag:
        shown = [f for f in shown if tag in f["tags"]]

    print_info(str(len(shown)) + "/" + str(len(all_f)) + " finding(s)")
    print()
    order = {s: i for i, s in enumerate(SEVERITY_LEVELS[::-1])}
    for f in sorted(shown, key=lambda x: (order.get(x["severity"], 0), -x["cvss"])):
        print(_render(f))

    out = Path(out_file) if out_file else REPORT_DIR / ("findings_list_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(shown, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── stats ──
def cmd_stats(out_file: str) -> int:
    all_f = _load_all()
    if not all_f:
        print_warn("no findings")
        return 0
    by_sev = {}
    by_mod = {}
    by_tgt = {}
    for f in all_f:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_mod[f["module"]] = by_mod.get(f["module"], 0) + 1
        if f["target"]:
            by_tgt[f["target"]] = by_tgt.get(f["target"], 0) + 1

    print_info("finding statistics")
    print_kv("total", len(all_f))
    print()
    print(BOLD + "by severity" + RESET)
    for s in SEVERITY_LEVELS[::-1]:
        if s in by_sev:
            col = SEVERITY_COLOR.get(s, ASH)
            print("  " + col + s.ljust(10) + RESET + BONE + str(by_sev[s]) + RESET)
    print()
    print(BOLD + "by module" + RESET)
    for m, c in sorted(by_mod.items(), key=lambda x: -x[1]):
        print("  " + ARTERY + m.ljust(20) + RESET + BONE + str(c) + RESET)
    print()
    print(BOLD + "by target" + RESET)
    for t, c in sorted(by_tgt.items(), key=lambda x: -x[1])[:20]:
        print("  " + CLOT + t[:50].ljust(50) + RESET + BONE + str(c) + RESET)

    out = Path(out_file) if out_file else REPORT_DIR / ("stats_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "total": len(all_f), "by_severity": by_sev,
        "by_module": by_mod, "by_target": by_tgt,
    }, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── score ──
def cmd_score(out_file: str) -> int:
    all_f = _load_all()
    if not all_f:
        print_warn("no findings")
        return 0
    sev_sum = sum(SEVERITY_WEIGHT.get(f["severity"], 1.0) for f in all_f)
    cvss_max = max((f["cvss"] for f in all_f), default=0.0)
    sev_max = max((SEVERITY_LEVELS.index(f["severity"]) for f in all_f), default=0)
    # overall = clip((severity_sum / 10) + (cvss_max), 0, 10)
    overall = min(10.0, round((sev_sum / 10.0) + cvss_max * 0.3, 2))

    print_info("overall risk score")
    print_kv("weighted severity sum", str(round(sev_sum, 2)))
    print_kv("max CVSS", str(cvss_max))
    print_kv("max severity", SEVERITY_LEVELS[sev_max])
    print_kv("overall (0-10)", str(overall))

    band = ("info" if overall < 1.5 else
            "low" if overall < 3.5 else
            "medium" if overall < 6.0 else
            "high" if overall < 8.5 else "critical")
    col = SEVERITY_COLOR.get(band, ASH)
    print()
    print(col + "risk band: " + band.upper() + RESET)

    out = Path(out_file) if out_file else REPORT_DIR / ("score_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "weighted_severity_sum": sev_sum,
        "max_cvss": cvss_max,
        "max_severity": SEVERITY_LEVELS[sev_max],
        "overall": overall,
        "band": band,
    }, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── dedupe ──
def cmd_dedupe(dry_run: bool) -> int:
    all_f = _load_all()
    seen = {}
    dupes = []
    for f in all_f:
        key = f["title"] + "|" + f["target"] + "|" + "|".join(sorted(f["evidence"]))
        key = hashlib.sha1(key.encode()).hexdigest()
        if key in seen:
            dupes.append((f, seen[key]))
        else:
            seen[key] = f

    print_info("dedupe scan")
    print_kv("kept", len(seen))
    print_kv("duplicates", len(dupes))
    for dup, kept in dupes[:20]:
        print("  " + ASH + dup["id"] + " == " + kept["id"] + "  " + dup["title"][:60] + RESET)

    if dry_run:
        print_info("dry-run — nothing removed")
        return 0
    for dup, _ in dupes:
        p = _finding_path(dup)
        if p.exists():
            p.unlink()
    print_ok("removed " + str(len(dupes)) + " duplicate(s)")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky report findings", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["add", "import", "list", "stats", "score", "dedupe"])
    p.add_argument("--module", default="manual")
    p.add_argument("--target", default="")
    p.add_argument("--title", default="")
    p.add_argument("--severity", default="medium",
                   choices=SEVERITY_LEVELS)
    p.add_argument("--cvss", type=float, default=0.0)
    p.add_argument("--remediation", default="")
    p.add_argument("--evidence", action="append", default=[])
    p.add_argument("--cwe", default="")
    p.add_argument("--tag", action="append", dest="tags", default=[])
    p.add_argument("--severity-filter", default="")
    p.add_argument("--module-filter", default="")
    p.add_argument("--target-filter", default="")
    p.add_argument("--tag-filter", default="")
    p.add_argument("--from-file", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky report findings <add|import|list|stats|score|dedupe> [opts]")
        return 2

    if ns.help:
        print_info("add     --title '...' --severity high --module cred_harvest --target 10.0.0.5")
        print_info("import  --from-file findings.json   # or pipe JSON to stdin with --from-file -")
        print_info("list    [--severity-filter high] [--module-filter cred] [--target-filter 10.0.0]")
        print_info("stats")
        print_info("score")
        print_info("dedupe  [--dry-run]")
        return 0

    if ns.action == "add":
        return cmd_add(ns.module, ns.target, ns.title, ns.severity, ns.cvss,
                       ns.remediation, ns.evidence, ns.cwe, ns.tags, ns.out)
    if ns.action == "import":
        return cmd_import(ns.from_file)
    if ns.action == "list":
        return cmd_list(ns.severity_filter, ns.module_filter, ns.target_filter,
                        ns.tag_filter, ns.out)
    if ns.action == "stats":
        return cmd_stats(ns.out)
    if ns.action == "score":
        return cmd_score(ns.out)
    if ns.action == "dedupe":
        return cmd_dedupe(ns.dry_run)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

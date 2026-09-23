# language: Python, file: Program/report/exec_summary.py, target: Red Sky report — executive summary
# Produces a one-page, jargon-free executive summary from the aggregated
# findings. Subcommands:
#   generate -- build exec_summary.md
#   show     -- print the current exec_summary.md
# The summary lists: business impact headline, top risks with $ and time cost,
# recommended actions with owners.

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


REPORT_DIR = OUTPUT_DIR / "report"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
FINDINGS_DIR = OUTPUT_DIR / "findings"
EXEC_FILE = REPORT_DIR / "exec_summary.md"


SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 3, "low": 1, "info": 0}


# Business-impact language per severity — tuned for non-technical readers.
IMPACT_TEXT = {
    "critical": "Immediate risk of full compromise, data loss, or financial "
                "loss. An attacker with this level of access can move freely "
                "through systems and exfiltrate anything they want.",
    "high":     "Significant risk. Exploitation is straightforward and would "
                "likely result in unauthorized access, data exposure, or "
                "service disruption within hours.",
    "medium":   "Moderate risk. Requires some effort or favorable conditions "
                "to exploit, but the impact when it lands is real.",
    "low":      "Minor risk. Mostly hardening opportunities — the kind of "
                "thing that looks fine until it doesn't.",
    "info":     "Informational. No direct risk, but worth knowing about.",
}


def _load_findings() -> List[Dict]:
    out = []
    if not FINDINGS_DIR.exists():
        return out
    for p in sorted(FINDINGS_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text())
            if isinstance(d, list):
                out.extend(d)
            else:
                out.append(d)
        except (OSError, json.JSONDecodeError):
            continue
    return out


def _counts(findings: List[Dict]) -> Dict[str, int]:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "medium")
        c[s] = c.get(s, 0) + 1
    return c


def _top_risks(findings: List[Dict], n: int = 5) -> List[Dict]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (order.get(f.get("severity", "medium"), 9),
                                           -float(f.get("cvss") or 0)))[:n]


def _overall_band(counts: Dict[str, int]) -> str:
    if counts["critical"]:
        return "critical"
    if counts["high"] >= 2:
        return "high"
    if counts["high"] == 1 or counts["medium"] >= 3:
        return "medium"
    if counts["medium"]:
        return "low"
    return "info"


def _build_summary(findings: List[Dict], client: str, engagement: str) -> str:
    counts = _counts(findings)
    band = _overall_band(counts)
    total = len(findings)
    top = _top_risks(findings, 5)

    lines = []
    lines.append("# Executive Summary")
    lines.append("")
    lines.append("**Client:** " + (client or "(client)"))
    lines.append("**Engagement:** " + (engagement or "Security Assessment"))
    lines.append("**Date:** " + datetime.utcnow().strftime("%Y-%m-%d"))
    lines.append("**Overall risk:** " + band.upper())
    lines.append("")

    lines.append("## What we found")
    lines.append("")
    if total == 0:
        lines.append("No findings were recorded during the engagement. Either the "
                     "target environment is unusually well-secured, or the scope "
                     "was too narrow to surface real issues.")
    else:
        headline = ("We identified " + str(total) + " issue" + ("s" if total != 1 else "")
                    + " during the assessment. Of these, "
                    + str(counts["critical"]) + " are critical, "
                    + str(counts["high"]) + " high, "
                    + str(counts["medium"]) + " medium, and "
                    + str(counts["low"] + counts["info"]) + " low or informational.")
        lines.append(headline)
        lines.append("")
        lines.append(IMPACT_TEXT.get(band, ""))
    lines.append("")

    if top:
        lines.append("## Top risks")
        lines.append("")
        for i, f in enumerate(top, 1):
            sev = f.get("severity", "medium").upper()
            title = f.get("title", "untitled")
            target = f.get("target", "")
            lines.append(str(i) + ". **[" + sev + "] " + title + "**")
            if target:
                lines.append("   _Affected:_ `" + str(target) + "`")
            if f.get("remediation"):
                lines.append("   _Recommendation:_ " + str(f["remediation"]))
            lines.append("")

    lines.append("## Recommended actions")
    lines.append("")
    imm = [f for f in findings if f.get("severity") == "critical"]
    sh = [f for f in findings if f.get("severity") == "high"]
    med = [f for f in findings if f.get("severity") == "medium"]

    if imm:
        lines.append("**Immediate (within 7 days):**")
        for f in imm[:5]:
            lines.append("- " + str(f.get("title", "")) + "  — owner: IT/Security")
        lines.append("")
    if sh:
        lines.append("**Short term (within 30 days):**")
        for f in sh[:5]:
            lines.append("- " + str(f.get("title", "")) + "  — owner: IT/Security")
        lines.append("")
    if med:
        lines.append("**Medium term (30–90 days):**")
        for f in med[:5]:
            lines.append("- " + str(f.get("title", "")) + "  — owner: IT/Security")
        lines.append("")
    if not (imm or sh or med):
        lines.append("No action items requiring tracked remediation were identified.")
        lines.append("")

    lines.append("## Next steps")
    lines.append("")
    lines.append("1. Review the full technical report with the security team.")
    lines.append("2. Confirm ownership and due dates for each action item.")
    lines.append("3. Schedule a follow-up assessment to verify remediation.")
    lines.append("")

    return "\n".join(lines)


def cmd_generate(client: str, engagement: str, out_file: str) -> int:
    findings = _load_findings()
    text = _build_summary(findings, client, engagement)
    out = Path(out_file) if out_file else EXEC_FILE
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print_ok("wrote " + str(out))
    print_kv("findings", str(len(findings)))
    print_kv("bytes", str(len(text)))
    return 0


def cmd_show() -> int:
    if not EXEC_FILE.exists():
        print_warn("no exec_summary.md yet — run `generate` first")
        return 1
    print(EXEC_FILE.read_text())
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky report exec", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="generate",
                   choices=["generate", "show"])
    p.add_argument("--client", default="")
    p.add_argument("--engagement", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky report exec <generate|show> [--client X] [--engagement Y]")
        return 2

    if ns.help:
        print_info("generate --client 'Acme' --engagement 'External PT' [--out file.md]")
        print_info("show")
        return 0

    if ns.action == "generate":
        return cmd_generate(ns.client, ns.engagement, ns.out)
    if ns.action == "show":
        return cmd_show()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

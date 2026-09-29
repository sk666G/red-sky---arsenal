# language: Python, file: Program/social/pretext.py, target: Red Sky social — pretext generation
# Social-engineering pretext library. Every pretext is a template whose
# placeholders ({target_name}, {target_email}, {company}, {attacker_name},
# {lure_url}, {callback_phone}, {deadline}) get filled from operator input.
#
# Categories of pretext:
#   it_support      — password reset / MFA / "we noticed suspicious activity"
#   hr              — payroll update / benefits / policy acknowledgment
#   security_alert  — "your account was accessed" / "verification required"
#   vendor          — invoice / quote / contract, often with an attachment
#   delivery        — package / courier / customs fee
#   exec            — CEO / CFO impersonation, urgency-driven
#   recruitment     — recruiter / hiring / role offer
#   helpdesk_mfa    — the classic "please approve this push" phone call
#
# Delivery channel and follow-up cadence accompany each pretext.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"
PRETEXT_DIR = SOCIAL_DIR / "pretexts"


PRETEXTS: Dict[str, Dict] = {
    "it_support": {
        "title": "IT support — password / MFA reset",
        "channel": "email or voice",
        "subject_lines": [
            "Action required: password expires in 24 hours",
            "Security notice: unusual sign-in on your account",
            "IT: scheduled MFA re-enrollment for your account",
            "Reset your {company} password to continue",
        ],
        "body": """Hi {target_name},

Our monitoring detected a sign-in to your {company} account from an
unrecognized device (IP 104.{fake_ip}). As a security precaution, we need
you to re-verify your identity and reset your password within the next
24 hours.

If you don't verify, your account will be temporarily suspended.

Verify now: {lure_url}

If you have any trouble, reply to this email or call IT at {callback_phone}.

Thanks,
{attacker_name}
{company} IT Support
""",
        "follow_up": [
            "1h later: DM/call — 'Did you get my email about the sign-in?'",
            "4h later: second email — 'This is time-sensitive.'",
            "24h later: escalation — 'Your account is now in a limited state.'",
        ],
    },
    "hr": {
        "title": "HR — payroll / benefits update",
        "channel": "email",
        "subject_lines": [
            "Action required: 2025 benefits enrollment",
            "Payroll update — direct deposit confirmation needed",
            "Important: policy acknowledgment due by Friday",
            "Employee handbook update — please sign",
        ],
        "body": """Hi {target_name},

Our payroll system is being upgraded for the new fiscal year, and we need
you to confirm your direct deposit details by Friday. Employees who don't
confirm will have their next pay cycle delayed.

Confirm here: {lure_url}

Login uses your existing {company} credentials.

Thanks,
{attacker_name}
{company} People Operations
""",
        "follow_up": [
            "Next day: reply-all bump from a 'colleague' — 'I just did this, quick'",
            "48h: HR follow-up — 'We're still missing your confirmation'",
        ],
    },
    "security_alert": {
        "title": "Security alert — suspicious activity",
        "channel": "email",
        "subject_lines": [
            "Security alert: someone accessed your {company} account",
            "Unusual sign-in from Russia — confirm or deny",
            "New device sign-in to your {company} account",
        ],
        "body": """{target_name},

We noticed a sign-in to your {company} account from Russia on {fake_date}
at 03:14 UTC. The device was an Android phone we haven't seen before.

If this wasn't you, secure your account now: {lure_url}

If this was you, you can safely ignore this message.

- {company} Security Team
""",
        "follow_up": [
            "30m later: SMS to phone — 'This is {company} security, please confirm'",
            "2h later: email — 'Your account has been temporarily locked'",
        ],
    },
    "vendor": {
        "title": "Vendor — invoice / purchase order",
        "channel": "email with attachment",
        "subject_lines": [
            "Invoice #{invoice_num} — payment due in 5 days",
            "Updated W-9 for {company} approval",
            "Quote for Q1 — see attached",
            "Contract renewal — signature required",
        ],
        "body": """Hello,

Attached is invoice #{invoice_num} for services rendered last month.
Payment terms are net-15, so please process promptly. If you need our
updated W-9 or banking details, those are in the attached PDF.

- A/R, {company}
{vendor_email}
""",
        "follow_up": [
            "3 days later: 'Any update on this invoice? Our finance team is asking.'",
            "7 days later: 'Second reminder — late fee will apply.'",
        ],
    },
    "delivery": {
        "title": "Delivery — package / customs",
        "channel": "SMS or email",
        "subject_lines": [
            "Your package could not be delivered",
            "Customs fee required for your shipment",
            "Delivery attempt failed — reschedule",
        ],
        "body": """Your package (tracking #{tracking}) could not be delivered because
a small customs fee was not paid.

Reschedule delivery and pay the fee: {lure_url}

The package will be returned to sender in 48 hours if not claimed.

- Delivery Support
""",
        "follow_up": [
            "24h later: SMS — 'Last attempt for your package.'",
        ],
    },
    "exec": {
        "title": "Executive — CEO / CFO impersonation",
        "channel": "email or SMS",
        "subject_lines": [
            "Quick favor",
            "Re: acquisition — need this by EOD",
            "Wire confirmation needed",
        ],
        "body": """{target_name} — need a quick favor. I'm in a board meeting, so
email only. We're closing on an acquisition and I need you to send a wire
confirmation to our counsel. Can you do this in the next 30 minutes? I'll
send the details as soon as you confirm.

- Sent from my iPhone

{attacker_name}, CEO
""",
        "follow_up": [
            "15m later: 'Have you seen my last message?'",
            "1h later: 'This is time-critical, please respond.'",
        ],
    },
    "recruitment": {
        "title": "Recruitment — LinkedIn / hiring",
        "channel": "LinkedIn DM or email",
        "subject_lines": [
            "Senior role at {company} — your profile matches",
            "Following up on the {role} opening",
            "Compensation details for {role} — strictly confidential",
        ],
        "body": """Hi {target_name},

I'm a recruiter working with {company} on a senior {role} search. Your
background looks like a great fit. Comp is in the {comp_range} range plus
equity.

If you're interested, take a look at the full JD and apply here:
{lure_url}

Happy to chat — my calendar is on the doc.

- {attacker_name}
Talent @ {company}
""",
        "follow_up": [
            "3 days later: 'Just following up — the team is moving fast.'",
            "1 week: 'They've narrowed to 3 finalists — do you want to be in?'",
        ],
    },
    "helpdesk_mfa": {
        "title": "Helpdesk MFA push fatigue (phone)",
        "channel": "voice",
        "script": """Ring script:

  "{target_name}, hi — this is {attacker_name} from {company} IT. We
   just pushed an MFA approval to your phone for a routine maintenance
   window. You should see the number pop up — could you approve it for
   me? I'm on a time-sensitive migration and yours is the last account
   we need."

If challenged:

  "Totally understand — I'm calling from extension {ext}. If you want
   to verify, hang up and call the helpdesk line, my ticket is #{ticket}."

If still challenged, close warmly and try the next target. Do NOT push.
""",
        "follow_up": [
            "Repeat 3-5 times over 10-15 min — push fatigue",
            "Escalate to voice call if MFA is happening (vishing the code)",
        ],
    },
}


def _fill(template: str, values: Dict[str, str]) -> str:
    out = template
    for k, v in values.items():
        out = out.replace("{" + k + "}", v or "")
    return out


def _defaults() -> Dict[str, str]:
    return {
        "target_name":    "Jordan Smith",
        "target_email":   "jordan.smith@example.com",
        "company":        "Acme Corp",
        "attacker_name":  "Alex Chen",
        "lure_url":       "https://login.acme-portal.com/verify",
        "callback_phone": "+1-555-0100",
        "deadline":       "24 hours",
        "role":           "Senior Engineer",
        "comp_range":     "$180-220k",
        "vendor_email":   "ar@acme-vendors.com",
        "invoice_num":    "INV-20841",
        "tracking":       "RS94118520US",
        "fake_ip":        "47.29",
        "fake_date":      "2025-11-14",
        "ext":            "2104",
        "ticket":         "HD-7719",
    }


def cmd_catalog() -> int:
    print_info("pretext catalog")
    print()
    for key, p in PRETEXTS.items():
        print("  " + SCARLET + key.ljust(16) + RESET + " " + BONE + p["title"] + RESET)
        print("      " + ASH + "channel: " + p["channel"] + RESET)
    print()
    print_info("run:  redsky social pretext show <category> [--target NAME] [--lure-url URL] [...]")
    print_info("      redsky social pretext all --out DIR [--lure-url URL]")
    return 0


def cmd_show(category: str, values: Dict[str, str]) -> int:
    if category not in PRETEXTS:
        print_err("unknown category: " + category)
        print_info("available: " + ", ".join(PRETEXTS.keys()))
        return 1
    p = PRETEXTS[category]
    merged = _defaults()
    merged.update({k: v for k, v in values.items() if v})

    print(SCARLET + BOLD + "== " + p["title"] + " ==" + RESET)
    print(ARTERY + "channel: " + RESET + p["channel"])
    print()
    if "subject_lines" in p:
        print(ARTERY + "subject lines:" + RESET)
        for s in p["subject_lines"]:
            print("  - " + _fill(s, merged))
        print()
    if "body" in p:
        print(ARTERY + "body:" + RESET)
        print(_fill(p["body"], merged))
    if "script" in p:
        print(ARTERY + "script:" + RESET)
        print(_fill(p["script"], merged))
    if "follow_up" in p:
        print()
        print(ARTERY + "follow-up cadence:" + RESET)
        for s in p["follow_up"]:
            print("  - " + _fill(s, merged))
    return 0


def cmd_all(out_dir: str, values: Dict[str, str]) -> int:
    d = Path(out_dir) if out_dir else PRETEXT_DIR / ("all_" + time.strftime("%Y%m%d_%H%M%S"))
    d.mkdir(parents=True, exist_ok=True)
    merged = _defaults()
    merged.update({k: v for k, v in values.items() if v})
    for key, p in PRETEXTS.items():
        lines = []
        lines.append("== " + p["title"] + " ==")
        lines.append("channel: " + p["channel"])
        lines.append("")
        if "subject_lines" in p:
            lines.append("subject lines:")
            for s in p["subject_lines"]:
                lines.append("  - " + _fill(s, merged))
            lines.append("")
        if "body" in p:
            lines.append("body:")
            lines.append(_fill(p["body"], merged))
        if "script" in p:
            lines.append("script:")
            lines.append(_fill(p["script"], merged))
        if "follow_up" in p:
            lines.append("")
            lines.append("follow-up cadence:")
            for s in p["follow_up"]:
                lines.append("  - " + _fill(s, merged))
        (d / (key + ".txt")).write_text("\n".join(lines))
        print_ok(key + " → " + str(d / (key + ".txt")))
    print()
    print_kv("dir", d)
    print_kv("categories", len(PRETEXTS))
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "catalog"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky social pretext <sub-command>")
        print_info("")
        print_info("  catalog                          list pretext categories")
        print_info("  show <category> [--target NAME] [--company NAME] [--lure-url URL] ...")
        print_info("      render one pretext with placeholders filled")
        print_info("  all [--out DIR] [--lure-url URL] [--target NAME] ...")
        print_info("      render every pretext to files")
        print_info("")
        print_info("categories: " + ", ".join(PRETEXTS.keys()))
        return 0

    if sub in ("catalog", "list"):
        return cmd_catalog()

    if sub == "show":
        p = argparse.ArgumentParser(prog="redsky social pretext show", add_help=False)
        p.add_argument("category")
        p.add_argument("--target", dest="target_name", default="")
        p.add_argument("--target-email", default="")
        p.add_argument("--company", default="")
        p.add_argument("--attacker", dest="attacker_name", default="")
        p.add_argument("--lure-url", default="")
        p.add_argument("--callback", dest="callback_phone", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social pretext show <category> [--target NAME] [...]")
            return 2
        values = {k: v for k, v in vars(ns).items() if k != "category" and v}
        return cmd_show(ns.category, values)

    if sub == "all":
        p = argparse.ArgumentParser(prog="redsky social pretext all", add_help=False)
        p.add_argument("--out", default="")
        p.add_argument("--target", dest="target_name", default="")
        p.add_argument("--company", default="")
        p.add_argument("--attacker", dest="attacker_name", default="")
        p.add_argument("--lure-url", default="")
        p.add_argument("--callback", dest="callback_phone", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social pretext all [--out DIR] [--target NAME] [...]")
            return 2
        values = {k: v for k, v in vars(ns).items() if k != "out" and v}
        return cmd_all(ns.out, values)

    print_err("unknown pretext sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

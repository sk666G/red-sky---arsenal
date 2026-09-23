# language: Python, file: Program/social/pretext.py, target: Red Sky social — pretext generator
# Generates ready-to-send pretexts across channels: email, phone/vishing script,
# LinkedIn DM, SMS, USB drop cover story, in-person social engineering.
# Templates + variables. Optional LLM polish hook for teams that want it.

import json
import random
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"
PRETEXT_DIR = SOCIAL_DIR / "pretexts"
PRETEXT_DIR.mkdir(parents=True, exist_ok=True)


# Each scenario: name, channel, when_to_use, fields (fill-ins), template
SCENARIOS: List[Dict] = [
    # ── EMAIL ──
    {
        "name": "it_password_reset",
        "channel": "email",
        "when": "target works in a corporate environment, mid-week, business hours",
        "fields": ["target_first_name", "company", "sender_name", "link"],
        "subject": "Action required: password expires in 24 hours",
        "body": """Hi {target_first_name},

Our records show your {company} account password is set to expire in 24 hours. To avoid losing access to email, Teams, and SharePoint, please reset it now using the link below.

{link}

If you've already reset your password in the last 7 days, you can ignore this message. If you need help, reply to this email or contact the helpdesk at extension 4357.

Thanks,
{sender_name}
IT Service Desk""",
    },
    {
        "name": "invoice_payment",
        "channel": "email",
        "when": "target has any finance/AP function, end of month",
        "fields": ["target_first_name", "vendor_name", "amount", "invoice_id", "link"],
        "subject": "Invoice {invoice_id} — payment due",
        "body": """Hi {target_first_name},

Please find attached invoice {invoice_id} from {vendor_name} for {amount}. Payment terms are net 15; please approve and schedule by end of week.

The invoice and remittance details are on our portal:
{link}

Let me know if you need anything else.

Regards,
{vendor_name} Accounts Receivable""",
    },
    {
        "name": "ceo_urgent",
        "channel": "email",
        "when": "target reports to or adjacent to an exec, Friday afternoon works best",
        "fields": ["target_first_name", "ceo_name", "task"],
        "subject": "Quick favor",
        "body": """{target_first_name} — are you at your desk?

I'm in back-to-back meetings and need {task} handled today. Can you grab it and let me know once it's done? Discretion appreciated.

Sent from my iPhone
{ceo_name}""",
    },
    {
        "name": "shared_document",
        "channel": "email",
        "when": "target is a knowledge worker, any time",
        "fields": ["target_first_name", "sender_name", "doc_title", "link"],
        "subject": "{sender_name} shared \"{doc_title}\" with you",
        "body": """{sender_name} has shared a document with you:

{doc_title}

Open in Google Drive / OneDrive:
{link}

You'll be prompted to sign in with your work account to view.

— File sharing service""",
    },
    # ── VISHING (phone script) ──
    {
        "name": "helpdesk_callback",
        "channel": "vishing",
        "when": "target is a regular helpdesk user, IT-familiar",
        "fields": ["target_first_name", "company", "sender_name", "ticket_id"],
        "script": """[Opening — warm, calm, no rush]

"Hi, is this {target_first_name}? Great — this is {sender_name} from {company} IT support. I'm calling about ticket {ticket_id} that came in this morning. Do you have a minute?"

[If yes]

"Thanks. We flagged some unusual sign-in activity on your account overnight — looks like someone trying to log in from outside the country. We've already locked it as a precaution. I need to re-verify you so we can unlock it."

[The ask — deliver without a pause]

"Can you confirm your current work email password so I can validate your session? Once we do that I'll unlock and reset it for you."

[If they hesitate]

"Totally understand — this is standard. If you'd rather, I can send you an email right now and you click the link, but the fix takes longer that way. Your call."

[If they give it]

"Perfect, thank you. I'm unlocking now. You'll get a reset email in the next five minutes — just click the link from that email, don't reply to it. Any questions for me before I let you go?"

[Close]

"Thanks for your time. Have a good rest of your day.""" ,
    },
    {
        "name": "bank_fraud_alert",
        "channel": "vishing",
        "when": "consumer target, any time but evenings land better",
        "fields": ["target_first_name", "bank_name", "amount", "card_last4"],
        "script": """[Opening]

"Hi, is this {target_first_name}? This is the fraud department at {bank_name}. I'm calling about a {amount} charge we saw hit your card ending {card_last4} about twenty minutes ago. Do you recognize that charge?"

[They say no]

"That's what I was afraid of. I'm going to block that merchant and reverse the charge, but first I need to verify you're the account holder. Standard security questions — I'll be quick."

[The ask — one question at a time, don't stack them]

"Can you confirm the email address on file and the last four of your SSN? Then I'll send a verification code to the phone number we have on file."

[Code interception]

"Great — code sent. Read it back to me when it arrives."

[Once code is provided — the attacker has completed the account takeover]

"Perfect, that's everything. You'll see the reversal in 24-48 hours. Anything else I can do for you?""" ,
    },
    # ── LINKEDIN DM ──
    {
        "name": "recruiter_dm",
        "channel": "linkedin",
        "when": "target has an up-to-date LinkedIn, active in the last 30 days",
        "fields": ["target_first_name", "sender_name", "role", "company", "link"],
        "body": """Hi {target_first_name} — I came across your profile and wanted to reach out. We're building out a {role} team at {company} and your background is exactly the kind we look for. Would you have 15 minutes this week for a quick chat?

Here's the role overview before you commit to a call:
{link}

No pressure at all — happy to just connect regardless.

— {sender_name}""",
    },
    {
        "name": "conference_followup",
        "channel": "linkedin",
        "when": "target attended a recent industry conference (check their feed)",
        "fields": ["target_first_name", "conference", "sender_name", "topic"],
        "body": """{target_first_name} — great to run into you at {conference} last week. I wanted to follow up on the {topic} conversation.

Attached my notes and the reference links we talked about:
{link}

Let's grab coffee if you're ever in town.

— {sender_name}""",
    },
    # ── SMS ──
    {
        "name": "parcel_delivery",
        "channel": "sms",
        "when": "consumer targets, any time",
        "fields": ["target_first_name", "courier", "link"],
        "body": """Hi {target_first_name}, {courier} here. Your parcel is on hold — the shipping address we have is incomplete. Update it within 24h or it returns to sender:

{link}""",
    },
    {
        "name": "mfa_prompt",
        "channel": "sms",
        "when": "target uses MFA on personal accounts",
        "fields": ["target_first_name", "service"],
        "body": """{target_first_name}, we've received a sign-in request for your {service} account from an unrecognized device. If this was not you, reply STOP to lock the account. If it was you, reply YES to approve.""",
    },
    # ── USB DROP ──
    {
        "name": "usb_payroll",
        "channel": "usb",
        "when": "target company has a physical lobby or parking lot",
        "fields": ["company", "quarter"],
        "body": """Lure: label the USB "Payroll — {company} — Q{quarter} final" and drop in the parking lot or lobby bathroom.

Cover story when confronted:
"I found this drive in the parking lot with your company's name on it — wanted to turn it in."

If the target plugs it in, the HID payload runs. Offer to leave it with reception as a plausibility move.""",
    },
    {
        "name": "usb_conference",
        "channel": "usb",
        "when": "industry conference with swag tables",
        "fields": ["conference"],
        "body": """Lure: label USB with {conference} branding + "session recordings" or "slide deck".

Drop method: leave several on the swag table, in the keynote hall, and on the coffee station.

Plausibility: attendees assume these are official conference materials. Insertion rate is highest in the first hour of the day.""",
    },
    # ── IN-PERSON ──
    {
        "name": "inperson_delivery",
        "channel": "in-person",
        "when": "target office has a walk-in reception",
        "fields": ["company", "target_first_name", "package"],
        "body": """Costume: delivery uniform (matching the courier for the building).

Prop: clipboard + cardboard box with the {company} logo + a signature sheet.

Script at reception:
"Delivery for {target_first_name} — need a signature. Which way is their desk?"

If they offer to take it: "Sorry, signature has to be from the named recipient — liability thing. I'll wait or I can find them."

Most reception staff will walk you back or point you at the right floor.""",
    },
]


def cmd_list() -> int:
    print_info(str(len(SCENARIOS)) + " pretext scenarios")
    print()
    by_channel: Dict[str, List[Dict]] = {}
    for s in SCENARIOS:
        by_channel.setdefault(s["channel"], []).append(s)
    for channel, scenarios in by_channel.items():
        print(ARTERY + BOLD + "-- " + channel + RESET)
        for s in scenarios:
            print("  " + SCARLET + "*" + RESET + " " + BONE + s["name"].ljust(22) + RESET
                  + " " + CLOT + s["when"] + RESET)
        print()
    return 0


def cmd_gen(scenario_name: str, channel: str, vars_str: str, out_file: str) -> int:
    # pick
    if scenario_name and scenario_name != "all":
        scenarios = [s for s in SCENARIOS if s["name"] == scenario_name]
        if not scenarios:
            print_err("unknown scenario: " + scenario_name)
            print_info("available: " + ", ".join(s["name"] for s in SCENARIOS))
            return 2
    elif channel and channel != "all":
        scenarios = [s for s in SCENARIOS if s["channel"] == channel]
    else:
        scenarios = SCENARIOS

    # parse vars like "target_first_name=Nono,company=Acme"
    vars_: Dict[str, str] = {}
    if vars_str:
        for pair in vars_str.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                vars_[k.strip()] = v.strip()

    results = []
    for s in scenarios:
        # default missing vars to placeholder
        filled = {}
        missing = []
        for f in s.get("fields", []):
            if f in vars_:
                filled[f] = vars_[f]
            else:
                filled[f] = "[" + f.upper() + "]"
                missing.append(f)

        out = {
            "name": s["name"],
            "channel": s["channel"],
            "when": s["when"],
            "missing_fields": missing,
        }
        if "subject" in s:
            out["subject"] = s["subject"].format(**filled)
        if "body" in s:
            out["body"] = s["body"].format(**filled)
        if "script" in s:
            out["script"] = s["script"].format(**filled)
        results.append(out)

    # pretty print
    for r in results:
        print(BOLD + SCARLET + r["name"] + RESET + "  (" + r["channel"] + ")")
        print(ASH + "when: " + RESET + r["when"])
        if r["missing_fields"]:
            print(WARN_FMT("missing: " + ", ".join(r["missing_fields"])))
        print()
        if "subject" in r:
            print(ARTERY + "Subject: " + RESET + BONE + r["subject"] + RESET)
            print()
        if "body" in r:
            print(r["body"])
        if "script" in r:
            print(r["script"])
        print()
        print(ASH + ("-" * 70) + RESET)
        print()

    out = Path(out_file) if out_file else PRETEXT_DIR / ("pretexts_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print_kv("saved", out)
    return 0


def WARN_FMT(s: str) -> str:
    # small helper — inline warning color without importing WARN
    from Program.theme.palette import SCARLET as _S, RESET as _R
    return _S + s + _R


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky social pretext", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "gen"])
    p.add_argument("scenario", nargs="?", default="all")
    p.add_argument("--channel", default="all",
                   choices=["email", "vishing", "linkedin", "sms", "usb", "in-person", "all"])
    p.add_argument("--vars", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky social pretext <list|gen> [scenario] [--channel C] [--vars 'k=v,k=v']")
        return 2

    if ns.help:
        print_info("list                                        -- show scenarios by channel")
        print_info("gen all --vars 'target_first_name=Nono,company=Acme,link=https://x/'")
        print_info("gen it_password_reset --vars '...'          -- one scenario")
        print_info("gen all --channel vishing                   -- only vishing")
        return 0

    if ns.action == "list":
        return cmd_list()
    return cmd_gen(ns.scenario, ns.channel, ns.vars, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

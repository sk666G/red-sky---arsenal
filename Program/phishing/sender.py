# language: Python, file: Program/phishing/sender.py, target: Red Sky phishing — link blaster
# Generates the personalized lure body from a template + target list, then
# dispatches via SMTP or a webhook-driven SMS gateway. Supports per-target
# tracking tokens so you know which recipient clicked.

import csv
import json
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage
from pathlib import Path
from string import Template
from typing import Dict, List

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


PH_DIR = OUTPUT_DIR / "phishing"
SEND_DIR = PH_DIR / "sends"


DEFAULT_TEMPLATE = """Subject: Action required: verify your account

Hi $first_name,

We detected a sign-in to your account from an unrecognized device.
Please confirm your identity within 24 hours to avoid suspension:

$link

Thanks,
$sender_name
"""


def _load_targets(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        return []
    if p.suffix.lower() == ".csv":
        rows = []
        with p.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append({k.strip(): (v or "").strip() for k, v in r.items()})
        return rows
    if p.suffix.lower() == ".json":
        try:
            data = json.loads(p.read_text())
            if isinstance(data, list):
                return data
        except Exception:
            return []
    # plain text — one email per line
    return [{"email": line.strip()} for line in p.read_text().splitlines() if line.strip()]


def _render(template: str, target: Dict, base_url: str, tracking: bool) -> Dict[str, str]:
    """Renders the template for a target. Returns {"subject": ..., "body": ..., "link": ...}."""
    # per-target token embedded in the URL
    token = ""
    if tracking:
        token = str(int(time.time())) + "-" + str(hash(target.get("email", "")) & 0xFFFFFFFF)
    link = base_url
    if tracking:
        sep = "&" if "?" in base_url else "?"
        link = base_url + sep + "t=" + token

    vars_ = {
        "first_name": target.get("first_name") or target.get("name", "").split(" ")[0] or "there",
        "last_name": target.get("last_name") or "",
        "email": target.get("email", ""),
        "link": link,
        "sender_name": target.get("sender_name", "Security Team"),
        "token": token,
    }
    rendered = Template(template).safe_substitute(vars_)
    subject = ""
    body = rendered
    if rendered.lower().startswith("subject:"):
        line, _, rest = rendered.partition("\n")
        subject = line[len("subject:"):].strip()
        body = rest.lstrip("\n")
    return {"subject": subject, "body": body, "link": link, "token": token}


def _send_smtp(host: str, port: int, user: str, password: str, tls: bool,
               from_addr: str, from_name: str, to_addr: str,
               subject: str, body: str, html: bool = False) -> bool:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = (from_name + " <" + from_addr + ">") if from_name else from_addr
    msg["To"] = to_addr
    if html:
        msg.set_content("Please view in HTML.")
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    try:
        if tls and port == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s:
                s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.ehlo()
                if tls:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if user:
                    s.login(user, password)
                s.send_message(msg)
        return True
    except Exception as e:
        print_err("smtp failed for " + to_addr + ": " + str(e))
        return False


def _send_webhook(webhook: str, target: Dict, subject: str, body: str, link: str) -> bool:
    """Post to a webhook — Discord/Slack style, or a generic JSON endpoint."""
    payload = {
        "to": target.get("email", ""),
        "subject": subject,
        "body": body,
        "link": link,
    }
    try:
        r = requests.post(webhook, json=payload, timeout=10)
        return r.status_code < 400
    except Exception as e:
        print_err("webhook failed: " + str(e))
        return False


def cmd_send(targets_path: str, template_path: str, base_url: str,
             channel: str, smtp_host: str, smtp_port: int, smtp_user: str,
             smtp_pass: str, smtp_tls: bool, from_addr: str, from_name: str,
             webhook: str, tracking: bool, dry_run: bool) -> int:
    PH_DIR.mkdir(parents=True, exist_ok=True)
    SEND_DIR.mkdir(parents=True, exist_ok=True)

    targets = _load_targets(targets_path)
    if not targets:
        print_err("no targets in " + targets_path)
        return 1

    template = DEFAULT_TEMPLATE
    if template_path:
        p = Path(template_path)
        if p.exists():
            template = p.read_text(encoding="utf-8")

    print_info("phishing send")
    print_kv("targets", len(targets))
    print_kv("channel", channel)
    print_kv("base_url", base_url)
    print_kv("tracking", "yes" if tracking else "no")
    if dry_run:
        print_warn("DRY RUN — nothing will be sent")
    print()

    session_id = str(int(time.time()))
    results = []

    for i, t in enumerate(targets, 1):
        rendered = _render(template, t, base_url, tracking)
        row = {
            "to": t.get("email", ""),
            "subject": rendered["subject"],
            "link": rendered["link"],
            "token": rendered["token"],
        }

        print("  " + ASH + "[" + str(i) + "/" + str(len(targets)) + "]" + RESET + " "
              + BONE + t.get("email", "") + RESET, end="")

        if dry_run:
            print("  " + ASH + "(dry)" + RESET)
            row["ok"] = True
            results.append(row)
            continue

        ok = False
        if channel == "smtp":
            ok = _send_smtp(smtp_host, smtp_port, smtp_user, smtp_pass, smtp_tls,
                            from_addr, from_name, t.get("email", ""),
                            rendered["subject"], rendered["body"])
        elif channel == "webhook":
            ok = _send_webhook(webhook, t, rendered["subject"], rendered["body"], rendered["link"])
        else:
            print_err("unknown channel: " + channel)
            return 2

        row["ok"] = ok
        results.append(row)
        print("  " + (SCARLET + "ok" if ok else CLOT + "fail") + RESET)

    out = SEND_DIR / ("send_" + session_id + ".json")
    out.write_text(json.dumps({"targets": len(targets), "channel": channel, "results": results}, indent=2))

    sent = sum(1 for r in results if r.get("ok"))
    print()
    print_kv("sent", str(sent) + "/" + str(len(results)))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky phishing sender", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--targets", required=False, default="")
    p.add_argument("--template", default="")
    p.add_argument("--base-url", default="")
    p.add_argument("--channel", default="smtp", choices=["smtp", "webhook"])
    p.add_argument("--smtp-host", default="")
    p.add_argument("--smtp-port", type=int, default=587)
    p.add_argument("--smtp-user", default="")
    p.add_argument("--smtp-pass", default="")
    p.add_argument("--smtp-tls", action="store_true")
    p.add_argument("--from-addr", default="")
    p.add_argument("--from-name", default="")
    p.add_argument("--webhook", default="")
    p.add_argument("--track", action="store_true")
    p.add_argument("--dry-run", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky phishing sender --targets file.csv --base-url https://phish.url --channel smtp ...")
        return 2

    if ns.help:
        print_info("redsky phishing sender --targets targets.csv --base-url https://collector.example.com/collect \\")
        print_info("    --channel smtp --smtp-host smtp.example.com --smtp-port 587 --smtp-user u --smtp-pass p --smtp-tls \\")
        print_info("    --from-addr security@example.com --from-name 'Security' --track")
        print_info("  targets.csv needs at least: email  (optional: first_name,last_name,sender_name)")
        print_info("  --dry-run prints rendered messages without sending")
        return 0

    if not ns.targets or not ns.base_url:
        print_err("--targets and --base-url are required")
        return 2
    if ns.channel == "smtp" and (not ns.smtp_host or not ns.from_addr):
        print_err("smtp channel needs --smtp-host and --from-addr")
        return 2
    if ns.channel == "webhook" and not ns.webhook:
        print_err("webhook channel needs --webhook")
        return 2

    return cmd_send(
        ns.targets, ns.template, ns.base_url,
        ns.channel, ns.smtp_host, ns.smtp_port, ns.smtp_user, ns.smtp_pass, ns.smtp_tls,
        ns.from_addr, ns.from_name, ns.webhook, ns.track, ns.dry_run,
    )


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/phish/mailer.py, target: Red Sky phish — mailer
# Send phishing emails via SMTP, SendGrid, or AWS SES. HTML with tracking pixel.

import json
import smtplib
import ssl
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


SEND_LOG = OUTPUT_DIR / "phish" / "sent.jsonl"


def _load_targets(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        return []
    if p.suffix.lower() == ".json":
        return json.loads(p.read_text())
    # csv: email,name
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "," not in line:
            continue
        parts = line.split(",", 1)
        out.append({"email": parts[0].strip(), "name": parts[1].strip()})
    return out


def _render(template: str, target: Dict, link: str, pixel: str) -> str:
    t = template
    t = t.replace("{{email}}", target.get("email", ""))
    t = t.replace("{{name}}", target.get("name", target.get("email", "").split("@")[0]))
    t = t.replace("{{link}}", link)
    t = t.replace("{{pixel}}", pixel)
    return t


def _send_smtp(host: str, port: int, user: str, passwd: str, use_tls: bool,
               from_addr: str, to_addr: str, subject: str, html: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.attach(MIMEText(html, "html"))

        if use_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.starttls(context=ctx)
                if user:
                    s.login(user, passwd)
                s.sendmail(from_addr, [to_addr], msg.as_string())
        else:
            with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                if user:
                    s.login(user, passwd)
                s.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except (smtplib.SMTPException, OSError) as e:
        print_warn(f"SMTP error: {e}")
        return False


def _send_sendgrid(api_key: str, from_addr: str, to_addr: str, subject: str, html: str) -> bool:
    try:
        r = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "personalizations": [{"to": [{"email": to_addr}]}],
                "from": {"email": from_addr},
                "subject": subject,
                "content": [{"type": "text/html", "value": html}],
            }, timeout=15)
        return r.status_code in (200, 202)
    except requests.RequestException as e:
        print_warn(f"sendgrid error: {e}")
        return False


def _send_ses(region: str, access_key: str, secret_key: str,
              from_addr: str, to_addr: str, subject: str, html: str) -> bool:
    # use AWS signature v4 via requests-aws4auth if available, else boto3
    try:
        import boto3
        client = boto3.client("ses", region_name=region,
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key)
        client.send_email(
            Source=from_addr,
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html}},
            })
        return True
    except Exception as e:
        print_warn(f"SES error: {e}")
        return False


def cmd_send(args: Dict) -> int:
    targets = _load_targets(args["targets"])
    if not targets:
        print_err(f"no targets loaded from {args['targets']}")
        return 1

    template_path = Path(args["template"])
    if not template_path.exists():
        print_err(f"template not found: {args['template']}")
        return 1
    template = template_path.read_text()

    print_info(f"sending to {len(targets)} target(s)")
    print_kv("from", args["from"])
    print_kv("subject", args["subject"])
    print_kv("relay", args["relay"])
    print()

    sent = 0
    failed = 0
    for t in targets:
        html = _render(template, t, args["link"], args.get("pixel", ""))

        ok = False
        if args["relay"] == "smtp":
            ok = _send_smtp(args["smtp_host"], args["smtp_port"],
                            args["smtp_user"], args["smtp_pass"],
                            args["smtp_tls"], args["from"], t["email"],
                            args["subject"], html)
        elif args["relay"] == "sendgrid":
            ok = _send_sendgrid(args["sendgrid_key"], args["from"], t["email"],
                                args["subject"], html)
        elif args["relay"] == "ses":
            ok = _send_ses(args["ses_region"], args["ses_key"], args["ses_secret"],
                           args["from"], t["email"], args["subject"], html)

        if ok:
            sent += 1
            print_ok(f"sent -> {t['email']}")
            with SEND_LOG.open("a") as f:
                f.write(json.dumps({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "to": t["email"], "subject": args["subject"], "relay": args["relay"],
                }) + "\n")
        else:
            failed += 1
            print_err(f"failed -> {t['email']}")

        time.sleep(args.get("delay", 0.5))

    print()
    print_kv("sent", sent)
    print_kv("failed", failed)
    return 0 if sent else 1


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky phish mailer", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--targets", required=False)
    p.add_argument("--template", required=False)
    p.add_argument("--from", dest="from_", required=False)
    p.add_argument("--subject", default="Important")
    p.add_argument("--link", default="https://example.tld")
    p.add_argument("--pixel", default="")
    p.add_argument("--relay", choices=["smtp", "sendgrid", "ses"], default="smtp")
    p.add_argument("--delay", type=float, default=0.5)
    # smtp
    p.add_argument("--smtp-host", default="")
    p.add_argument("--smtp-port", type=int, default=587)
    p.add_argument("--smtp-user", default="")
    p.add_argument("--smtp-pass", default="")
    p.add_argument("--smtp-tls", action="store_true", default=True)
    # sendgrid
    p.add_argument("--sendgrid-key", default="")
    # ses
    p.add_argument("--ses-region", default="us-east-1")
    p.add_argument("--ses-key", default="")
    p.add_argument("--ses-secret", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky phish mailer --targets <file> --template <file> --from <addr> ...")
        return 2

    if ns.help:
        print_info("redsky phish mailer --targets <file> --template <file> --from <addr> --subject S --link URL")
        print_info("  --relay smtp --smtp-host H --smtp-user U --smtp-pass P")
        print_info("  --relay sendgrid --sendgrid-key K")
        print_info("  --relay ses --ses-region R --ses-key K --ses-secret S")
        return 0

    if not (ns.targets and ns.template and ns.from_):
        print_err("--targets --template --from required")
        return 2

    return cmd_send({
        "targets": ns.targets,
        "template": ns.template,
        "from": ns.from_,
        "subject": ns.subject,
        "link": ns.link,
        "pixel": ns.pixel,
        "relay": ns.relay,
        "delay": ns.delay,
        "smtp_host": ns.smtp_host,
        "smtp_port": ns.smtp_port,
        "smtp_user": ns.smtp_user,
        "smtp_pass": ns.smtp_pass,
        "smtp_tls": ns.smtp_tls,
        "sendgrid_key": ns.sendgrid_key,
        "ses_region": ns.ses_region,
        "ses_key": ns.ses_key,
        "ses_secret": ns.ses_secret,
    })


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

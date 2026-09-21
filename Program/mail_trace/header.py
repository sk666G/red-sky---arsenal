# language: Python, file: Program/mail_trace/header.py, target: Red Sky mail_trace — header analysis
# Parses a raw email header, extracts the delivery chain, checks the sending
# domain for SPF / DKIM / DMARC, and reports whether the domain is spoofable.

import re
import sys
from email import message_from_string
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


MT_DIR = OUTPUT_DIR / "mail_trace"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


def _dns_query(name: str, rtype: str) -> List[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, rtype, lifetime=8)
        return [str(a).rstrip(".") if hasattr(a, "to_text") else str(a) for a in answers]
    except Exception:
        return []


def parse_headers(raw: str) -> Dict:
    """Take a raw header block and pull the interesting fields."""
    # normalize line endings
    raw = raw.replace("\r\n", "\n")

    # if it's a full email, take just headers up to the first blank line
    if "\n\n" in raw:
        header_part = raw.split("\n\n", 1)[0]
    else:
        header_part = raw

    msg = message_from_string(header_part)

    received = msg.get_all("Received", [])
    headers = {k: msg.get(k, "") for k in (
        "From", "To", "Cc", "Reply-To", "Return-Path", "Delivered-To",
        "Subject", "Date", "Message-ID",
        "Authentication-Results", "Received-SPF", "DKIM-Signature",
        "X-Originating-IP", "X-Sender-IP", "X-Mailer", "User-Agent",
        "X-Forwarded-For", "X-Forwarded-To",
        "ARC-Authentication-Results",
    )}

    # unique X-Originating-IP values
    xo = msg.get_all("X-Originating-IP", []) or []
    headers["X-Originating-IP-all"] = [str(x).strip("[]") for x in xo]

    return {"headers": headers, "received_chain": received}


def _from_domain(headers: Dict) -> str:
    f = headers.get("From", "")
    m = re.search(r"@([A-Za-z0-9._-]+)", f)
    return m.group(1).lower() if m else ""


def _return_path_domain(headers: Dict) -> str:
    rp = headers.get("Return-Path", "")
    m = re.search(r"@([A-Za-z0-9._-]+)", rp)
    return m.group(1).lower() if m else ""


def check_spf(domain: str) -> Dict:
    if not domain:
        return {"present": False}
    txt = _dns_query(domain, "TXT")
    spf_records = [t for t in txt if "v=spf1" in t]
    if not spf_records:
        return {"present": False}
    record = spf_records[0]
    policy_all = "?"
    if "-all" in record:
        policy_all = "hardfail (-all)"
    elif "~all" in record:
        policy_all = "softfail (~all)"
    elif "?all" in record:
        policy_all = "neutral (?all)"
    elif "+all" in record:
        policy_all = "PASS-ALL (+all) — spoofable"
    return {"present": True, "record": record, "policy": policy_all}


def check_dmarc(domain: str) -> Dict:
    if not domain:
        return {"present": False}
    txt = _dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in txt if "v=DMARC1" in t]
    if not dmarc:
        return {"present": False}
    record = dmarc[0]
    policy = "none"
    m = re.search(r"\bp=(\w+)", record)
    if m:
        policy = m.group(1)
    return {"present": True, "record": record, "policy": policy}


def check_dkim_selector(domain: str, selector: str) -> Dict:
    if not domain or not selector:
        return {"present": False}
    txt = _dns_query(f"{selector}._domainkey.{domain}", "TXT")
    dkim = [t for t in txt if "v=DKIM1" in t or "k=" in t or "p=" in t]
    return {"present": bool(dkim), "record": dkim[0] if dkim else ""}


def check_mx(domain: str) -> List[str]:
    return _dns_query(domain, "MX")


def cmd_analyze(source: str) -> int:
    """source can be a file path or the raw header string."""
    MT_DIR.mkdir(parents=True, exist_ok=True)

    p = Path(source)
    if p.exists() and p.is_file():
        raw = p.read_text(encoding="utf-8", errors="replace")
        origin = str(p)
    else:
        raw = source
        origin = "inline"

    print_info(f"analyzing header from: {origin}")
    print()

    parsed = parse_headers(raw)
    headers = parsed["headers"]
    chain = parsed["received_chain"]

    # basic identity
    print(f"{ARTERY}{BOLD}── identity{RESET}")
    for k in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"):
        v = headers.get(k, "")
        if v:
            print_kv(k, v[:120])
    print()

    from_dom = _from_domain(headers)
    rp_dom = _return_path_domain(headers)
    print_kv("From domain", from_dom or "?")
    print_kv("Return-Path domain", rp_dom or "?")
    if from_dom and rp_dom and from_dom != rp_dom:
        print_warn("From domain != Return-Path domain — common with spoofed mail")
    print()

    # auth results
    print(f"{ARTERY}{BOLD}── authentication{RESET}")
    ar = headers.get("Authentication-Results", "")
    if ar:
        for line in ar.split(";"):
            line = line.strip()
            if line:
                print(f"  {ARTERY}▓{RESET} {BONE}{line[:100]}{RESET}")
    else:
        print(f"  {ASH}no Authentication-Results header{RESET}")
    print()

    # SPF
    spf = check_spf(from_dom)
    print(f"{ARTERY}{BOLD}── SPF{RESET}")
    if spf["present"]:
        print_ok(f"present")
        print_kv("record", spf["record"][:100])
        print_kv("policy", spf["policy"])
    else:
        print_warn("no SPF record — From: domain can be spoofed freely")
    print()

    # DMARC
    dmarc = check_dmarc(from_dom)
    print(f"{ARTERY}{BOLD}── DMARC{RESET}")
    if dmarc["present"]:
        print_ok(f"present")
        print_kv("record", dmarc["record"][:100])
        print_kv("policy", dmarc["policy"])
        if dmarc["policy"] == "none":
            print_warn("p=none — monitoring only, mail is not rejected on spoof")
    else:
        print_warn("no DMARC record — spoofing is trivial if SPF also missing")
    print()

    # DKIM — try common selectors if header has DKIM-Signature
    dkim_hdr = headers.get("DKIM-Signature", "")
    selector = ""
    m = re.search(r"\bs=([A-Za-z0-9_-]+)", dkim_hdr)
    if m:
        selector = m.group(1)
    if selector:
        dkim = check_dkim_selector(from_dom, selector)
        print(f"{ARTERY}{BOLD}── DKIM (selector: {selector}){RESET}")
        if dkim["present"]:
            print_ok("public key present")
            print_kv("record", dkim["record"][:100])
        else:
            print_warn(f"no DKIM record at {selector}._domainkey.{from_dom}")
        print()

    # MX
    mx = check_mx(from_dom)
    print(f"{ARTERY}{BOLD}── MX records{RESET}")
    if mx:
        for m in mx[:5]:
            print(f"  {ARTERY}▓{RESET} {BONE}{m}{RESET}")
    else:
        print(f"  {ASH}none{RESET}")
    print()

    # received chain
    print(f"{ARTERY}{BOLD}── delivery chain ({len(chain)} hops){RESET}")
    for i, hop in enumerate(chain):
        first = hop.split("\n", 1)[0]
        print(f"  {ARTERY}▓{RESET} {ASH}{i+1}{RESET}  {BONE}{first[:120]}{RESET}")

    # spoofing verdict
    print()
    print(f"{ARTERY}{BOLD}── spoofability verdict{RESET}")
    spoofable = True
    reasons = []
    if not spf["present"]:
        reasons.append("no SPF")
    elif "+all" in spf.get("record", ""):
        reasons.append("SPF has +all")
    if not dmarc["present"]:
        reasons.append("no DMARC")
    elif dmarc.get("policy") == "none":
        reasons.append("DMARC p=none")
    if not reasons:
        spoofable = False
        print_ok("not trivially spoofable — SPF and DMARC policies are enforced")
    else:
        print_warn(f"spoofable: {', '.join(reasons)}")

    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky mail_trace analyze <header-file|inline-header-string>")
        return 2
    return cmd_analyze(args[0])


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

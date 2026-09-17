#!/usr/bin/env python3
# language: Python, file: Data/update_cve.py, target: Red Sky — standalone CVE + Exploit-DB indexer
# Pulls NVD CVE data and the Exploit-DB CSV index into Data/.
# Run directly: python3 Data/update_cve.py
# Or via:      python3 redsky.py recon update-cve

import csv
import io
import json
import sys
import time
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DATA_DIR = REPO_ROOT / "Data"
CVE_FILE = DATA_DIR / "cve_db.json"
EDB_FILE = DATA_DIR / "edb_db.json"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# products we care about — matches what Red Sky fingerprints
NVD_KEYWORDS = [
    "nginx", "apache", "httpd", "iis", "tomcat", "jetty", "undertow",
    "wordpress", "drupal", "joomla", "magento", "woocommerce", "shopify",
    "laravel", "django", "flask", "fastapi", "rails", "express",
    "spring", "struts", "weblogic", "jboss", "wildfly", "log4j",
    "exchange", "sharepoint", "citrix", "fortinet", "fortios", "sonicwall",
    "f5", "big-ip", "vmware", "vcenter", "esxi",
    "confluence", "jira", "jenkins", "gitlab", "grafana", "kibana",
    "elasticsearch", "openssh", "openssl", "redis", "mongodb", "mysql",
    "postgresql", "mariadb", "mssql", "oracle",
]


def _score(metrics):
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(k) or []
        if arr:
            data = arr[0].get("cvssData", {})
            return float(data.get("baseScore", 0.0)), data.get("baseSeverity", "").upper()
    return 0.0, ""


def pull_nvd(per_keyword=200):
    print("[*] pulling CVE index from NVD (services.nvd.nist.gov)")
    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Accept": "application/json"})

    all_cves = {}
    for kw in NVD_KEYWORDS:
        try:
            r = session.get(NVD_BASE, params={
                "keywordSearch": kw,
                "resultsPerPage": per_keyword,
                "startIndex": 0,
            }, timeout=30)
            if r.status_code == 429:
                print(f"    rate limited on {kw}, waiting 6s")
                time.sleep(6)
                r = session.get(NVD_BASE, params={
                    "keywordSearch": kw,
                    "resultsPerPage": per_keyword,
                    "startIndex": 0,
                }, timeout=30)
            if r.status_code != 200:
                print(f"    {kw} -> HTTP {r.status_code}")
                continue
            data = r.json()
        except (requests.RequestException, json.JSONDecodeError) as e:
            print(f"    {kw} failed: {e}")
            continue

        got = 0
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cid = cve.get("id", "")
            if not cid:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc:
                continue
            score, sev = _score(cve.get("metrics", {}))
            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
            triggers = {kw}
            low = desc.lower()
            for k2 in NVD_KEYWORDS:
                if k2 in low:
                    triggers.add(k2)
            all_cves[cid] = {
                "id": cid,
                "cvss": score,
                "severity": sev,
                "summary": desc[:500],
                "matches": sorted(triggers),
                "poc": refs[:5],
            }
            got += 1
        print(f"    {kw:<14} {got} CVEs")
        time.sleep(6.5)

    existing = {}
    if CVE_FILE.exists():
        try:
            for c in json.loads(CVE_FILE.read_text()):
                existing[c["id"]] = c
        except (json.JSONDecodeError, KeyError):
            pass

    for cid, c in all_cves.items():
        existing[cid] = c

    final = sorted(existing.values(), key=lambda x: x.get("cvss", 0), reverse=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CVE_FILE.write_text(json.dumps(final, indent=2))
    print(f"[+] NVD index: {len(final)} CVEs -> {CVE_FILE}")
    return len(final)


def pull_edb():
    """Pull Exploit-DB CSV index. Gives us CVE -> public PoC mapping without a network round trip."""
    print("[*] pulling Exploit-DB index")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    try:
        r = requests.get(url, timeout=60, headers={"User-Agent": UA})
        if r.status_code != 200:
            print(f"    HTTP {r.status_code}, skipping EDB")
            return 0
    except requests.RequestException as e:
        print(f"    failed: {e}")
        return 0

    edb = {}
    reader = csv.DictReader(io.StringIO(r.text))
    for row in reader:
        cve_field = (row.get("codes") or "").strip()
        for token in cve_field.replace(";", ",").split(","):
            token = token.strip()
            if token.startswith("CVE-"):
                edb.setdefault(token, []).append({
                    "edb_id": row.get("id"),
                    "title": row.get("description", "")[:200],
                    "url": f"https://www.exploit-db.com/exploits/{row.get('id')}",
                    "type": row.get("type", ""),
                    "platform": row.get("platform", ""),
                })

    EDB_FILE.write_text(json.dumps(edb, indent=2))
    print(f"[+] EDB index: {len(edb)} CVEs -> {EDB_FILE}")
    return len(edb)


def main():
    nvd = pull_nvd()
    edb = pull_edb()
    print(f"[+] done. NVD={nvd}, EDB={edb}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

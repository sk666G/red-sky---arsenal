# language: Python, file: Program/recon/subs.py, target: Red Sky recon — subdomain enum
# DNS brute (bundled wordlist), certificate transparency (crt.sh), zone transfer attempt.

import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


# small bundled wordlist — 150 common subdomains
WORDLIST = """
www
mail
remote
blog
webmail
server
ns1
ns2
ns3
ns4
smtp
secure
vpn
m
shop
ftp
mail2
test
portal
ns
ww1
host
support
dev
web
bbs
mx
email
cloud
1
2
3
mail3
api
cdn
app
staging
stage
demo
beta
alpha
admin
administrator
internal
intranet
corp
office
exchange
owa
autodiscover
lyncdiscover
sip
meet
conference
media
video
stream
assets
static
img
images
css
js
files
download
downloads
upload
uploads
proxy
gateway
gw
router
firewall
fw
dns
dns1
dns2
ldap
ad
dc
dc1
dc2
dc3
db
database
mysql
postgres
sql
oracle
mssql
redis
mongo
elastic
kibana
grafana
prometheus
jenkins
git
gitlab
github
bitbucket
svn
repo
repos
jira
confluence
wiki
docs
help
kb
support
status
monitor
monitoring
nagios
zabbix
cacti
backup
backups
bak
old
legacy
archive
temp
tmp
new
sandbox
lab
labs
qa
uat
prod
production
live
edge
origin
node
node1
node2
web1
web2
web3
srv
srv1
srv2
docker
k8s
kubernetes
rancher
openshift
vcenter
esxi
vmware
citrix
rdp
remote1
remote2
""".split()


def _resolve(host: str) -> List[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return ips
    except socket.gaierror:
        return []


def _check_sub(sub: str, domain: str) -> dict:
    fqdn = f"{sub}.{domain}"
    ips = _resolve(fqdn)
    if ips:
        return {"sub": fqdn, "ips": ips, "source": "brute"}
    return {}


def brute(domain: str, threads: int = 64) -> List[dict]:
    print_info(f"DNS brute — {len(WORDLIST)} entries across {threads} threads")
    found = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(_check_sub, w, domain) for w in WORDLIST]
        for f in as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
                print_ok(f"{r['sub']:<40} {', '.join(r['ips'])}")
    return found


def crtsh(domain: str) -> List[dict]:
    print_info("certificate transparency via crt.sh")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            print_warn(f"crt.sh returned {r.status_code}")
            return []
        data = r.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print_warn(f"crt.sh failed: {e}")
        return []

    names: Set[str] = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith("." + domain):
                names.add(name)

    found = []
    for n in sorted(names):
        ips = _resolve(n)
        if ips:
            found.append({"sub": n, "ips": ips, "source": "crt.sh"})
            print_ok(f"{n:<40} {', '.join(ips)}")
    return found


def zone_transfer(domain: str) -> List[dict]:
    print_info("attempting zone transfer (AXFR)")
    try:
        import dns.resolver
        import dns.query
        import dns.zone
    except ImportError:
        print_warn("dnspython not installed — skipping AXFR")
        return []

    ns_records = []
    try:
        answers = dns.resolver.resolve(domain, "NS")
        ns_records = [str(r.target).rstrip(".") for r in answers]
    except Exception as e:
        print_warn(f"NS lookup failed: {e}")
        return []

    found = []
    for ns in ns_records:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
            for name in z.nodes.keys():
                fqdn = str(name) + "." + domain if str(name) != "@" else domain
                ips = _resolve(fqdn)
                if ips:
                    found.append({"sub": fqdn, "ips": ips, "source": f"axfr/{ns}"})
                    print_ok(f"{fqdn:<40} {', '.join(ips)}")
        except Exception:
            continue
    return found


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky recon subs <domain> [mode]")
        print_err("  mode: brute | crtsh | axfr | all (default: all)")
        return 2

    domain = args[0].strip().lower()
    mode = args[1] if len(args) > 1 else "all"

    print_info(f"enumerating subdomains of {domain}")
    print()

    results: List[dict] = []
    if mode in ("brute", "all"):
        results += brute(domain)
    if mode in ("crtsh", "all"):
        results += crtsh(domain)
    if mode in ("axfr", "all"):
        results += zone_transfer(domain)

    # dedupe by sub name
    seen = set()
    uniq = []
    for r in results:
        if r["sub"] not in seen:
            seen.add(r["sub"])
            uniq.append(r)

    print()
    print_kv("total", len(uniq))

    out = OUTPUT_DIR / f"subs_{domain}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for r in uniq:
            f.write(f"{r['sub']}\t{','.join(r['ips'])}\t{r['source']}\n")
    print_kv("saved", out)
    return 0


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

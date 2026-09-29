# language: Python, file: Program/cloud/iam_enum.py, target: Red Sky cloud — IAM enumeration
# Cloud IAM enumeration. Given AWS credentials (via env, profile, or the
# metadata service), walk the account's identity surface:
#
#   1. Who am I?              sts:GetCallerIdentity
#   2. What account / ARN?    from the identity response
#   3. What users/roles exist? iam:ListUsers, iam:ListRoles, iam:ListGroups
#   4. What policies attach?  iam:ListAttachedUserPolicies + iam:GetPolicyVersion
#   5. What can I do?         iam:SimulatePrincipalPolicy on a candidate action list
#   6. Any inline policies?   iam:ListUserPolicies + GetUserPolicy
#
# Prefers boto3. Falls back to pure SigV4 requests if boto3 is missing.

import base64
import datetime
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
IAM_DIR = CLOUD_DIR / "iam"


# ── boto3 driver (preferred) ────────────────────────────────────────────────

def _boto3():
    try:
        import boto3  # type: ignore
        return boto3
    except ImportError:
        return None


def _session(profile: str, region: str):
    b3 = _boto3()
    if b3 is None:
        return None
    if profile:
        return b3.Session(profile_name=profile, region_name=region)
    return b3.Session(region_name=region)


# ── SigV4 fallback (no boto3) ───────────────────────────────────────────────

def _sigv4(method: str, host: str, path: str, query: Dict[str, str],
           service: str, region: str, access_key: str, secret_key: str,
           session_token: str = "") -> Dict[str, str]:
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_uri = path
    canonical_qs = "&".join(
        urllib.parse.quote(k, safe="") + "=" + urllib.parse.quote(v, safe="")
        for k, v in sorted(query.items())
    )
    canonical_headers = "host:" + host + "\n" + "x-amz-date:" + amz_date + "\n"
    if session_token:
        canonical_headers += "x-amz-security-token:" + session_token + "\n"
    signed_headers = "host;x-amz-date" + (";x-amz-security-token" if session_token else "")

    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join([
        method, canonical_uri, canonical_qs,
        canonical_headers, signed_headers, payload_hash,
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = "/".join([date_stamp, region, service, "aws4_request"])
    string_to_sign = "\n".join([
        algorithm, amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (algorithm + " Credential=" + access_key + "/" + credential_scope +
            ", SignedHeaders=" + signed_headers + ", Signature=" + signature)

    headers = {
        "Host": host,
        "x-amz-date": amz_date,
        "Authorization": auth,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    return headers


def _sigv4_post(host: str, path: str, data: Dict[str, str],
                service: str, region: str,
                access_key: str, secret_key: str,
                session_token: str = "", timeout: int = 15) -> Optional[str]:
    try:
        import requests
    except ImportError:
        return None
    body = urllib.parse.urlencode(data)
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode()).hexdigest()

    headers_for_signing = "content-type:application/x-www-form-urlencoded; charset=utf-8\n" \
                          "host:" + host + "\n" \
                          "x-amz-date:" + amz_date + "\n"
    if session_token:
        headers_for_signing += "x-amz-security-token:" + session_token + "\n"
    signed = "content-type;host;x-amz-date" + (";x-amz-security-token" if session_token else "")

    canonical = "\n".join(["POST", path, "", headers_for_signing, signed, payload_hash])
    scope = "/".join([date_stamp, region, service, "aws4_request"])
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                      hashlib.sha256(canonical.encode()).hexdigest()])

    def _s(k, m):
        return hmac.new(k, m.encode(), hashlib.sha256).digest()

    k = _s(("AWS4" + secret_key).encode(), date_stamp)
    k = _s(k, region); k = _s(k, service); k = _s(k, "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    auth = ("AWS4-HMAC-SHA256 Credential=" + access_key + "/" + scope +
            ", SignedHeaders=" + signed + ", Signature=" + sig)

    req_headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "x-amz-date": amz_date,
        "Authorization": auth,
    }
    if session_token:
        req_headers["x-amz-security-token"] = session_token

    try:
        r = requests.post("https://" + host + path, headers=req_headers, data=body, timeout=timeout)
        return r.text
    except Exception as e:
        return json.dumps({"__error__": str(e)})


# ── walk ────────────────────────────────────────────────────────────────────

# A candidate action list for SimulatePrincipalPolicy. Covers common privesc
# and recon actions on AWS.
PROBE_ACTIONS = [
    "iam:CreateAccessKey", "iam:CreateUser", "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile", "iam:AddUserToGroup", "iam:AttachUserPolicy",
    "iam:AttachRolePolicy", "iam:AttachGroupPolicy", "iam:PutUserPolicy",
    "iam:PutRolePolicy", "iam:PutGroupPolicy", "iam:PassRole",
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy", "iam:CreateRole", "iam:CreateInstanceProfile",
    "iam:AddRoleToInstanceProfile", "iam:TagRole",
    "sts:AssumeRole", "sts:GetCallerIdentity", "sts:GetFederationToken",
    "ec2:*", "s3:*", "lambda:*", "dynamodb:*", "secretsmanager:*",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
    "kms:Decrypt", "kms:Encrypt", "kms:CreateGrant",
]


def cmd_whoami(profile: str, region: str) -> int:
    sess = _session(profile, region)
    if sess is not None:
        try:
            sts = sess.client("sts")
            ident = sts.get_caller_identity()
            print_ok("identity (boto3)")
            for k, v in ident.items():
                print_kv(k, v)
            return 0
        except Exception as e:
            print_err("boto3 sts: " + str(e))
            return 1

    # fallback — env creds + sigv4
    ak = os.environ.get("AWS_ACCESS_KEY_ID", "")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    st = os.environ.get("AWS_SESSION_TOKEN", "")
    if not ak or not sk:
        print_err("no AWS creds (boto3 missing, and env vars absent)")
        print_info("set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or install boto3")
        return 1
    body = _sigv4_post("sts.amazonaws.com", "/", {"Action": "GetCallerIdentity", "Version": "2011-06-15"},
                       "sts", "us-east-1", ak, sk, st)
    print(body or "(no response)")
    return 0


def cmd_walk(profile: str, region: str, out: str) -> int:
    sess = _session(profile, region)
    if sess is None:
        print_err("walk requires boto3 — pip install boto3")
        return 1

    IAM_DIR.mkdir(parents=True, exist_ok=True)
    print_info("AWS IAM walk")
    print_kv("profile", profile or "(default)")
    print_kv("region", region)
    print()

    report: Dict = {"identity": None, "users": [], "roles": [], "groups": [], "self_simulate": []}

    try:
        sts = sess.client("sts")
        ident = sts.get_caller_identity()
        report["identity"] = ident
        print(SCARLET + "identity" + RESET)
        for k, v in ident.items():
            print_kv(" " + k, v)
        me = ident.get("Arn", "")
        print()
    except Exception as e:
        print_err("sts: " + str(e))
        return 1

    iam = sess.client("iam")

    # users
    try:
        users = iam.list_users().get("Users", [])
        print(SCARLET + "users (" + str(len(users)) + ")" + RESET)
        for u in users[:50]:
            report["users"].append({"UserName": u["UserName"], "Arn": u["Arn"],
                                    "CreateDate": str(u.get("CreateDate", ""))})
            print("  " + BONE + u["UserName"] + RESET + " " + ASH + u["Arn"] + RESET)
        print()
    except Exception as e:
        print_warn("list_users: " + str(e))

    # roles
    try:
        roles = iam.list_roles().get("Roles", [])
        print(SCARLET + "roles (" + str(len(roles)) + ")" + RESET)
        for r in roles[:50]:
            report["roles"].append({"RoleName": r["RoleName"], "Arn": r["Arn"]})
            print("  " + BONE + r["RoleName"] + RESET + " " + ASH + r["Arn"] + RESET)
        print()
    except Exception as e:
        print_warn("list_roles: " + str(e))

    # groups
    try:
        groups = iam.list_groups().get("Groups", [])
        print(SCARLET + "groups (" + str(len(groups)) + ")" + RESET)
        for g in groups[:50]:
            report["groups"].append({"GroupName": g["GroupName"], "Arn": g["Arn"]})
            print("  " + BONE + g["GroupName"] + RESET)
        print()
    except Exception as e:
        print_warn("list_groups: " + str(e))

    # whoami policies
    try:
        if ":user/" in me:
            uname = me.split("/")[-1]
            attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
            inline = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
            groups_ = iam.list_groups_for_user(UserName=uname).get("Groups", [])
            print(SCARLET + "my policies" + RESET)
            for p in attached:
                print("  " + BONE + "attached: " + p["PolicyName"] + RESET + " " + ASH + p["PolicyArn"] + RESET)
            for p in inline:
                print("  " + BONE + "inline: " + p + RESET)
            for g in groups_:
                print("  " + BONE + "via group: " + g["GroupName"] + RESET)
            print()
    except Exception as e:
        print_warn("self policies: " + str(e))

    # simulate
    try:
        sim = iam.simulate_principal_policy(
            PolicySourceArn=me,
            ActionNames=PROBE_ACTIONS,
        )
        results = sim.get("EvaluationResults", [])
        allowed = [r for r in results if r.get("EvalDecision") == "allowed"]
        print(SCARLET + "simulate (" + str(len(allowed)) + "/" + str(len(PROBE_ACTIONS)) + " allowed)" + RESET)
        for r in allowed[:80]:
            print("  " + SCARLET + "ALLOW" + RESET + " " + BONE + r["EvalActionName"] + RESET)
            report["self_simulate"].append(r["EvalActionName"])
        print()
    except Exception as e:
        print_warn("simulate_principal_policy: " + str(e))

    out_path = Path(out) if out else IAM_DIR / ("walk_" + time.strftime("%Y%m%d_%H%M%S") + ".json")
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print_kv("saved", out_path)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky cloud iam_enum <sub-command>")
        print_info("")
        print_info("  whoami [--profile P] [--region R]")
        print_info("      sts:GetCallerIdentity — who are these creds")
        print_info("  walk  [--profile P] [--region R] [--out FILE]")
        print_info("      full IAM walk: users, roles, groups, my policies, simulate")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--profile", default="")
    base.add_argument("--region", default="us-east-1")

    if sub in ("whoami", "id"):
        p = argparse.ArgumentParser(prog="redsky cloud iam_enum whoami", parents=[base], add_help=False)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky cloud iam_enum whoami [--profile P] [--region R]")
            return 2
        return cmd_whoami(ns.profile, ns.region)

    if sub in ("walk", "enum"):
        p = argparse.ArgumentParser(prog="redsky cloud iam_enum walk", parents=[base], add_help=False)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky cloud iam_enum walk [--profile P] [--region R] [--out FILE]")
            return 2
        return cmd_walk(ns.profile, ns.region, ns.out)

    print_err("unknown iam_enum sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

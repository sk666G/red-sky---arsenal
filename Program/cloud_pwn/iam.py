# language: Python, file: Program/cloud_pwn/iam.py, target: Red Sky cloud_pwn — IAM enumeration
# Takes AWS credentials (from metadata, env, or user input) and enumerates
# what they can do, then detects known privesc chains. Uses boto3.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud_pwn"


# Known AWS privesc patterns. Each entry: (required_permission, technique, note)
PRIVESC_PATTERNS = [
    ("iam:CreatePolicyVersion",        "create-policy-version",    "Create new policy version with admin *"),
    ("iam:SetDefaultPolicyVersion",    "set-default-policy",       "Roll back to an old admin policy version"),
    ("iam:PassRole+ec2:RunInstances",  "passrole-ec2",             "Launch EC2 with admin role attached"),
    ("iam:PassRole+lambda:CreateFunction+lambda:InvokeFunction",
                                       "passrole-lambda",          "Lambda executes with admin role"),
    ("iam:PassRole+glue:CreateDevEndpoint",
                                       "passrole-glue",            "Glue DevEndpoint with admin role"),
    ("iam:CreateAccessKey",            "create-access-key",        "Create access key for another user"),
    ("iam:CreateLoginProfile",         "create-login-profile",     "Set console password on a user"),
    ("iam:UpdateLoginProfile",         "update-login-profile",     "Change another user's console password"),
    ("iam:AttachUserPolicy",           "attach-user-policy",       "Attach AdministratorAccess to self"),
    ("iam:AttachGroupPolicy",          "attach-group-policy",      "Attach admin policy to a group you're in"),
    ("iam:AttachRolePolicy+sts:AssumeRole",
                                       "attach-role-policy",       "Attach admin policy to assumable role"),
    ("iam:PutUserPolicy",              "put-user-policy",          "Inline admin policy on self"),
    ("iam:PutGroupPolicy",             "put-group-policy",         "Inline admin policy on group"),
    ("iam:PutRolePolicy+sts:AssumeRole",
                                       "put-role-policy",          "Inline admin policy on assumable role"),
    ("iam:AddUserToGroup",             "add-user-to-group",        "Add self to an admin group"),
    ("iam:UpdateAssumeRolePolicy+sts:AssumeRole",
                                       "update-assume-role",       "Modify trust policy to assume admin role"),
    ("sts:AssumeRole",                 "assume-role",              "Assume a more privileged role"),
    ("lambda:UpdateFunctionCode",      "lambda-update-code",       "Backdoor existing Lambda function"),
    ("glue:UpdateDevEndpoint",         "glue-update-endpoint",     "Update Glue endpoint SSH key"),
    ("ssm:SendCommand",                "ssm-send-command",         "Run commands on EC2 via SSM"),
    ("ecs:RegisterTaskDefinition+ecs:RunTask",
                                       "ecs-task",                 "ECS task with host privileges"),
]


def _make_session(access_key="", secret_key="", session_token="", region="us-east-1"):
    try:
        import boto3
    except ImportError:
        print_err("boto3 not installed")
        print_info("  pip install --break-system-packages boto3")
        return None
    if access_key and secret_key:
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token or None,
            region_name=region,
        )
    # pick up from env / ~/.aws
    return boto3.Session(region_name=region)


def cmd_whoami(access_key="", secret_key="", session_token="", region="us-east-1"):
    session = _make_session(access_key, secret_key, session_token, region)
    if not session:
        return 1

    sts = session.client("sts")
    try:
        ident = sts.get_caller_identity()
        print_ok("credentials valid")
        print_kv("Account", ident.get("Account"))
        print_kv("Arn", ident.get("Arn"))
        print_kv("UserId", ident.get("UserId"))
        return 0
    except Exception as e:
        print_err(f"sts:GetCallerIdentity failed: {e}")
        return 1


def cmd_enum(access_key="", secret_key="", session_token="", region="us-east-1", out_file=""):
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)
    session = _make_session(access_key, secret_key, session_token, region)
    if not session:
        return 1

    sts = session.client("sts")
    iam = session.client("iam")

    try:
        ident = sts.get_caller_identity()
    except Exception as e:
        print_err(f"sts failed: {e}")
        return 1

    print_info("IAM enumeration")
    print_kv("Account", ident.get("Account"))
    print_kv("Arn", ident.get("Arn"))
    print()

    result = {"identity": ident, "policies": [], "inline_policies": [], "groups": [],
              "attached_policies": [], "assumed_roles": []}

    # attached policies on the current user
    try:
        arn = ident["Arn"]
        if ":user/" in arn:
            user_name = arn.split(":user/", 1)[1]
            att = iam.list_attached_user_policies(UserName=user_name)
            for p in att.get("AttachedPolicies", []):
                result["attached_policies"].append(p)
                print(f"  {ARTERY}▓{RESET} {BONE}attached: {p['PolicyName']}{RESET}")
            inline = iam.list_user_policies(UserName=user_name)
            for name in inline.get("PolicyNames", []):
                result["inline_policies"].append(name)
                print(f"  {ARTERY}▓{RESET} {BONE}inline: {name}{RESET}")
            grps = iam.list_groups_for_user(UserName=user_name)
            for g in grps.get("Groups", []):
                result["groups"].append(g["GroupName"])
                print(f"  {ARTERY}▓{RESET} {BONE}group: {g['GroupName']}{RESET}")
    except Exception as e:
        print_warn(f"policy enumeration failed: {e}")

    # can we list all users?
    try:
        users = iam.list_users(MaxItems=100)
        result["all_users"] = [u["UserName"] for u in users.get("Users", [])]
        print()
        print_ok(f"{len(result['all_users'])} users in account")
    except Exception as e:
        print_warn(f"iam:ListUsers denied: {e}")

    # can we list roles?
    try:
        roles = iam.list_roles(MaxItems=100)
        result["roles"] = [r["RoleName"] for r in roles.get("Roles", [])]
        print_ok(f"{len(result['roles'])} roles in account")
    except Exception as e:
        print_warn(f"iam:ListRoles denied: {e}")

    out = Path(out_file) if out_file else CLOUD_DIR / f"iam_{ident.get('Account', 'unknown')}_{int(time.time())}.json"
    out.write_text(json.dumps(result, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def cmd_privesc(access_key="", secret_key="", session_token="", region="us-east-1"):
    session = _make_session(access_key, secret_key, session_token, region)
    if not session:
        return 1

    sts = session.client("sts")
    iam = session.client("iam")
    try:
        arn = sts.get_caller_identity()["Arn"]
    except Exception as e:
        print_err(f"sts failed: {e}")
        return 1

    print_info("privesc chain detection")
    print_kv("principal", arn)
    print()

    # gather effective permissions — parse attached policies
    effective = set()

    try:
        if ":user/" in arn:
            user_name = arn.split(":user/", 1)[1]
            for p in iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []):
                effective.update(_actions_from_policy(iam, p["PolicyArn"]))
            for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
                doc = iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"]
                effective.update(_actions_from_document(doc))
            for g in iam.list_groups_for_user(UserName=user_name).get("Groups", []):
                for p in iam.list_attached_group_policies(GroupName=g["GroupName"]).get("AttachedPolicies", []):
                    effective.update(_actions_from_policy(iam, p["PolicyArn"]))
    except Exception as e:
        print_warn(f"policy walk incomplete: {e}")

    effective.add("*")  # if we can't enumerate, assume star — will show false positives

    print_ok(f"{len(effective)} distinct permission(s) resolved")

    hits = []
    for pattern, technique, note in PRIVESC_PATTERNS:
        parts = pattern.split("+")
        if all(p in effective for p in parts):
            hits.append({"pattern": pattern, "technique": technique, "note": note})
            print(f"  {SCARLET}▓{RESET} {BONE}{technique}{RESET} — {ASH}{note}{RESET}")

    if not hits:
        print_warn("no known privesc chain matched (may still have one)")

    out = CLOUD_DIR / f"privesc_{int(time.time())}.json"
    out.write_text(json.dumps({"principal": arn, "permissions": sorted(effective), "chains": hits}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def _actions_from_policy(iam, policy_arn):
    actions = set()
    try:
        versions = iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
        for v in versions:
            if v.get("IsDefaultVersion"):
                doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])["PolicyVersion"]["Document"]
                actions.update(_actions_from_document(doc))
    except Exception:
        pass
    return actions


def _actions_from_document(doc):
    actions = set()
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        if s.get("Effect") != "Allow":
            continue
        a = s.get("Action", [])
        if isinstance(a, str):
            a = [a]
        actions.update(a)
    return actions


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud_pwn iam", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="whoami")
    p.add_argument("--access-key", default="")
    p.add_argument("--secret-key", default="")
    p.add_argument("--session-token", default="")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud_pwn iam <whoami|enum|privesc> [--access-key K --secret-key K]")
        return 2

    if ns.help:
        print_info("redsky cloud_pwn iam whoami [--access-key K --secret-key K --session-token T]")
        print_info("redsky cloud_pwn iam enum   same flags + [--region R]")
        print_info("redsky cloud_pwn iam privesc")
        print_info("  with no keys, boto3 uses env vars or ~/.aws")
        return 0

    if ns.action == "whoami":
        return cmd_whoami(ns.access_key, ns.secret_key, ns.session_token, ns.region)
    if ns.action == "enum":
        return cmd_enum(ns.access_key, ns.secret_key, ns.session_token, ns.region, ns.out)
    if ns.action == "privesc":
        return cmd_privesc(ns.access_key, ns.secret_key, ns.session_token, ns.region)
    print_err(f"unknown iam action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

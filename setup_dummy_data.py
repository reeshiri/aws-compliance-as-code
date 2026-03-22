"""
setup_dummy_data.py - creates realistic dummy AWS resources for compliance testing

Creates:
  - Two VPCs (CDE and non-CDE) with subnets, route tables, NACLs
  - Security groups with intentional misconfigurations (for interesting findings)
  - IAM users with varying compliance posture (MFA on/off, stale keys, etc.)
  - S3 buckets (one intentionally public for findings)
  - A dummy password policy

Run:
    python setup_dummy_data.py --region us-east-1 [--profile your-profile]

Clean up everything it created:
    python setup_dummy_data.py --region us-east-1 --destroy
"""

import argparse
import boto3
import json
import time
from datetime import datetime, timezone

# Tag applied to every resource so --destroy can find and remove them
TAG_KEY = "ManagedBy"
TAG_VALUE = "compliance-dummy-data"
TAGS = [{"Key": TAG_KEY, "Value": TAG_VALUE}]
TAGS_DICT = {TAG_KEY: TAG_VALUE}


def tag_filter():
    return [{"Name": f"tag:{TAG_KEY}", "Values": [TAG_VALUE]}]


# ── Helpers ────────────────────────────────────────────────────────────────

def log(msg):
    print(f"  {msg}")


def ok(msg):
    print(f"  ✓  {msg}")


def section(title):
    print(f"\n{'─'*56}")
    print(f"  {title}")
    print(f"{'─'*56}")


# ── VPC / Network ──────────────────────────────────────────────────────────

def create_networks(ec2):
    section("VPCs and subnets")

    # CDE VPC - cardholder data environment (should be isolated)
    cde_vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")
    cde_vpc_id = cde_vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[cde_vpc_id], Tags=TAGS + [
        {"Key": "Name", "Value": "cde-vpc"},
        {"Key": "Environment", "Value": "CDE"},
    ])
    ok(f"CDE VPC: {cde_vpc_id}")

    # Non-CDE VPC - general workloads
    corp_vpc = ec2.create_vpc(CidrBlock="10.2.0.0/16")
    corp_vpc_id = corp_vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[corp_vpc_id], Tags=TAGS + [
        {"Key": "Name", "Value": "corp-vpc"},
        {"Key": "Environment", "Value": "Corporate"},
    ])
    ok(f"Corporate VPC: {corp_vpc_id}")

    # CDE subnets
    cde_private = ec2.create_subnet(VpcId=cde_vpc_id, CidrBlock="10.1.1.0/24",
                                     AvailabilityZone=get_az(ec2))
    cde_private_id = cde_private["Subnet"]["SubnetId"]
    ec2.create_tags(Resources=[cde_private_id], Tags=TAGS + [
        {"Key": "Name", "Value": "cde-private"},
        {"Key": "Tier", "Value": "private"},
    ])
    ok(f"CDE private subnet: {cde_private_id}")

    cde_public = ec2.create_subnet(VpcId=cde_vpc_id, CidrBlock="10.1.2.0/24",
                                    AvailabilityZone=get_az(ec2))
    cde_public_id = cde_public["Subnet"]["SubnetId"]
    ec2.create_tags(Resources=[cde_public_id], Tags=TAGS + [
        {"Key": "Name", "Value": "cde-public"},
        {"Key": "Tier", "Value": "public"},
    ])
    ok(f"CDE public subnet: {cde_public_id}")

    # Corporate subnets
    corp_subnet = ec2.create_subnet(VpcId=corp_vpc_id, CidrBlock="10.2.1.0/24",
                                     AvailabilityZone=get_az(ec2))
    corp_subnet_id = corp_subnet["Subnet"]["SubnetId"]
    ec2.create_tags(Resources=[corp_subnet_id], Tags=TAGS + [
        {"Key": "Name", "Value": "corp-general"},
    ])
    ok(f"Corporate subnet: {corp_subnet_id}")

    return {
        "cde_vpc_id": cde_vpc_id,
        "corp_vpc_id": corp_vpc_id,
        "cde_private_id": cde_private_id,
        "cde_public_id": cde_public_id,
        "corp_subnet_id": corp_subnet_id,
    }


def get_az(ec2):
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    return azs[0]["ZoneName"]


def create_nacls(ec2, net):
    section("Network ACLs")

    # CDE NACL - intentionally restrictive (good posture)
    cde_nacl = ec2.create_network_acl(VpcId=net["cde_vpc_id"])
    cde_nacl_id = cde_nacl["NetworkAcl"]["NetworkAclId"]
    ec2.create_tags(Resources=[cde_nacl_id], Tags=TAGS + [
        {"Key": "Name", "Value": "cde-nacl"},
    ])

    # Inbound: allow HTTPS only from corporate range
    ec2.create_network_acl_entry(
        NetworkAclId=cde_nacl_id, RuleNumber=100, Protocol="6",
        RuleAction="allow", Egress=False,
        CidrBlock="10.2.0.0/16",
        PortRange={"From": 443, "To": 443},
    )
    # Inbound: deny everything else
    ec2.create_network_acl_entry(
        NetworkAclId=cde_nacl_id, RuleNumber=32766, Protocol="-1",
        RuleAction="deny", Egress=False, CidrBlock="0.0.0.0/0",
    )
    # Outbound: allow established connections back
    ec2.create_network_acl_entry(
        NetworkAclId=cde_nacl_id, RuleNumber=100, Protocol="6",
        RuleAction="allow", Egress=True,
        CidrBlock="10.2.0.0/16",
        PortRange={"From": 1024, "To": 65535},
    )
    ok(f"CDE NACL (restrictive): {cde_nacl_id}")

    # Corporate NACL - overly permissive (intentional misconfiguration for findings)
    corp_nacl = ec2.create_network_acl(VpcId=net["corp_vpc_id"])
    corp_nacl_id = corp_nacl["NetworkAcl"]["NetworkAclId"]
    ec2.create_tags(Resources=[corp_nacl_id], Tags=TAGS + [
        {"Key": "Name", "Value": "corp-nacl-permissive"},
    ])
    # Allow all inbound (misconfiguration - will show in findings)
    ec2.create_network_acl_entry(
        NetworkAclId=corp_nacl_id, RuleNumber=100, Protocol="-1",
        RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0",
    )
    ec2.create_network_acl_entry(
        NetworkAclId=corp_nacl_id, RuleNumber=100, Protocol="-1",
        RuleAction="allow", Egress=True, CidrBlock="0.0.0.0/0",
    )
    ok(f"Corporate NACL (permissive - intentional finding): {corp_nacl_id}")

    return {"cde_nacl_id": cde_nacl_id, "corp_nacl_id": corp_nacl_id}


def create_security_groups(ec2, net):
    section("Security groups")

    sgs = {}

    # CDE web tier - HTTPS only (good posture)
    cde_web = ec2.create_security_group(
        GroupName="cde-web-tier",
        Description="CDE web tier - HTTPS only inbound",
        VpcId=net["cde_vpc_id"],
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": TAGS + [{"Key": "Name", "Value": "cde-web-tier"}]}],
    )
    cde_web_id = cde_web["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=cde_web_id, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS public"}]},
    ])
    ok(f"CDE web SG (HTTPS only): {cde_web_id}")
    sgs["cde_web"] = cde_web_id

    # CDE app tier - only accepts traffic from web tier (good posture)
    cde_app = ec2.create_security_group(
        GroupName="cde-app-tier",
        Description="CDE app tier - internal only",
        VpcId=net["cde_vpc_id"],
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": TAGS + [{"Key": "Name", "Value": "cde-app-tier"}]}],
    )
    cde_app_id = cde_app["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=cde_app_id, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
         "UserIdGroupPairs": [{"GroupId": cde_web_id,
                               "Description": "From web tier only"}]},
    ])
    ok(f"CDE app SG (web tier only): {cde_app_id}")
    sgs["cde_app"] = cde_app_id

    # Misconfigured SG - SSH open to the world (intentional finding)
    bad_ssh = ec2.create_security_group(
        GroupName="corp-legacy-ssh-open",
        Description="Legacy server - SSH open to world (DO NOT USE IN PROD)",
        VpcId=net["corp_vpc_id"],
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": TAGS + [{"Key": "Name", "Value": "corp-legacy-ssh"}]}],
    )
    bad_ssh_id = bad_ssh["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=bad_ssh_id, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH - intentional finding"}]},
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
         "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "RDP - intentional finding"}]},
    ])
    ok(f"Legacy SG (SSH+RDP open - intentional finding): {bad_ssh_id}")
    sgs["bad_ssh"] = bad_ssh_id

    # Misconfigured SG - all ports open internally (intentional finding)
    bad_internal = ec2.create_security_group(
        GroupName="corp-all-ports-internal",
        Description="Overly permissive internal SG",
        VpcId=net["corp_vpc_id"],
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": TAGS + [{"Key": "Name", "Value": "corp-all-ports"}]}],
    )
    bad_internal_id = bad_internal["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=bad_internal_id, IpPermissions=[
        {"IpProtocol": "-1",
         "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "All internal - intentional finding"}]},
    ])
    ok(f"Permissive internal SG (all ports - intentional finding): {bad_internal_id}")
    sgs["bad_internal"] = bad_internal_id

    return sgs


# ── IAM ────────────────────────────────────────────────────────────────────

def create_iam_users(iam):
    section("IAM users")

    users = []

    # User 1 - good posture (MFA on, recent key)
    try:
        iam.create_user(UserName="svc-compliant-user",
                        Tags=TAGS + [{"Key": "Description",
                                      "Value": "Compliant service account"}])
        key = iam.create_access_key(UserName="svc-compliant-user")["AccessKey"]
        ok(f"svc-compliant-user (access key created, no MFA - MFA requires physical device)")
        users.append("svc-compliant-user")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("svc-compliant-user already exists, skipping")

    # User 2 - console user without MFA (intentional finding)
    try:
        iam.create_user(UserName="alice-no-mfa",
                        Tags=TAGS + [{"Key": "Description",
                                      "Value": "Console user without MFA - intentional finding"}])
        iam.create_login_profile(UserName="alice-no-mfa",
                                  Password="Dummy@Password1!",
                                  PasswordResetRequired=True)
        ok(f"alice-no-mfa (console access, no MFA - intentional finding)")
        users.append("alice-no-mfa")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("alice-no-mfa already exists, skipping")

    # User 3 - console user without MFA (intentional finding)
    try:
        iam.create_user(UserName="bob-no-mfa",
                        Tags=TAGS + [{"Key": "Description",
                                      "Value": "Console user without MFA - intentional finding"}])
        iam.create_login_profile(UserName="bob-no-mfa",
                                  Password="Dummy@Password2!",
                                  PasswordResetRequired=True)
        ok(f"bob-no-mfa (console access, no MFA - intentional finding)")
        users.append("bob-no-mfa")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("bob-no-mfa already exists, skipping")

    # User 4 - service account with two access keys (intentional finding)
    try:
        iam.create_user(UserName="svc-dual-keys",
                        Tags=TAGS + [{"Key": "Description",
                                      "Value": "Service account with multiple keys - finding"}])
        iam.create_access_key(UserName="svc-dual-keys")
        iam.create_access_key(UserName="svc-dual-keys")
        ok(f"svc-dual-keys (two active access keys - intentional finding)")
        users.append("svc-dual-keys")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("svc-dual-keys already exists, skipping")

    # User 5 - read-only analyst (good posture, no console, no keys)
    try:
        iam.create_user(UserName="analyst-readonly",
                        Tags=TAGS + [{"Key": "Description",
                                      "Value": "Read-only analyst no console or keys"}])
        iam.attach_user_policy(UserName="analyst-readonly",
                                PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
        ok(f"analyst-readonly (no console, no keys - good posture)")
        users.append("analyst-readonly")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("analyst-readonly already exists, skipping")

    return users


def create_iam_groups_and_roles(iam):
    section("IAM groups and roles")

    # CDE access group
    try:
        iam.create_group(GroupName="cde-access-group")
        iam.create_tags(ResourceName="cde-access-group",
                        Tags=TAGS + [{"Key": "Name", "Value": "cde-access-group"}])
        ok("Group: cde-access-group")
    except Exception:
        ok("cde-access-group already exists, skipping")

    # Read-only group
    try:
        iam.create_group(GroupName="readonly-analysts")
        iam.attach_group_policy(GroupName="readonly-analysts",
                                 PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
        ok("Group: readonly-analysts (ReadOnlyAccess attached)")
    except Exception:
        ok("readonly-analysts already exists, skipping")

    # Application role with least-privilege (good posture)
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
    })
    try:
        iam.create_role(
            RoleName="cde-app-role",
            AssumeRolePolicyDocument=trust,
            Description="Least-privilege role for CDE application tier",
            Tags=TAGS + [{"Key": "Name", "Value": "cde-app-role"}],
        )
        ok("Role: cde-app-role (EC2 trust, least privilege)")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("cde-app-role already exists, skipping")

    # Overly permissive role (intentional finding)
    try:
        iam.create_role(
            RoleName="corp-admin-overpermissioned",
            AssumeRolePolicyDocument=trust,
            Description="Overpermissioned role - intentional finding",
            Tags=TAGS + [{"Key": "Name", "Value": "corp-admin-overpermissioned"}],
        )
        iam.attach_role_policy(RoleName="corp-admin-overpermissioned",
                                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        ok("Role: corp-admin-overpermissioned (AdministratorAccess - intentional finding)")
    except iam.exceptions.EntityAlreadyExistsException:
        ok("corp-admin-overpermissioned already exists, skipping")


# ── S3 ─────────────────────────────────────────────────────────────────────

def create_s3_buckets(s3, s3_control, account_id, region):
    section("S3 buckets")

    import random, string
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

    # Private bucket - good posture
    private_bucket = f"compliance-demo-private-{suffix}"
    kwargs = {"Bucket": private_bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=private_bucket,
                           Tagging={"TagSet": TAGS + [{"Key": "Name",
                                                        "Value": "private-data-store"}]})
    s3.put_bucket_versioning(Bucket=private_bucket,
                              VersioningConfiguration={"Status": "Enabled"})
    s3.put_public_access_block(
        Bucket=private_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    ok(f"Private bucket (versioned, public access blocked): {private_bucket}")

    # Public bucket - intentional misconfiguration for findings
    public_bucket = f"compliance-demo-public-{suffix}"
    kwargs2 = {"Bucket": public_bucket}
    if region != "us-east-1":
        kwargs2["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs2)
    s3.put_bucket_tagging(Bucket=public_bucket,
                           Tagging={"TagSet": TAGS + [{"Key": "Name",
                                                        "Value": "intentional-public-finding"}]})
    # Leave public access block OFF - will trigger s3-bucket-public-read-prohibited
    ok(f"Public bucket (no block - intentional finding): {public_bucket}")

    return [private_bucket, public_bucket]


# ── Destroy ────────────────────────────────────────────────────────────────

def destroy(session, region):
    section("Destroying all dummy resources")

    ec2 = session.client("ec2", region_name=region)
    iam = session.client("iam")
    s3 = session.client("s3")

    # S3 buckets
    try:
        buckets = s3.list_buckets()["Buckets"]
        for b in buckets:
            name = b["Name"]
            try:
                tags = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
                if any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags):
                    # Empty and delete
                    paginator = s3.get_paginator("list_objects_v2")
                    for page in paginator.paginate(Bucket=name):
                        for obj in page.get("Contents", []):
                            s3.delete_object(Bucket=name, Key=obj["Key"])
                    s3.delete_bucket(Bucket=name)
                    ok(f"Deleted bucket: {name}")
            except Exception:
                pass
    except Exception as e:
        log(f"S3 cleanup error: {e}")

    # IAM users
    for username in ["svc-compliant-user", "alice-no-mfa", "bob-no-mfa",
                     "svc-dual-keys", "analyst-readonly"]:
        try:
            # Detach policies
            for p in iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]:
                iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])
            # Delete access keys
            for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=username, AccessKeyId=k["AccessKeyId"])
            # Delete login profile
            try:
                iam.delete_login_profile(UserName=username)
            except Exception:
                pass
            iam.delete_user(UserName=username)
            ok(f"Deleted IAM user: {username}")
        except Exception:
            pass

    # IAM groups
    for group in ["cde-access-group", "readonly-analysts"]:
        try:
            for p in iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]:
                iam.detach_group_policy(GroupName=group, PolicyArn=p["PolicyArn"])
            iam.delete_group(GroupName=group)
            ok(f"Deleted IAM group: {group}")
        except Exception:
            pass

    # IAM roles
    for role in ["cde-app-role", "corp-admin-overpermissioned"]:
        try:
            for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role, PolicyArn=p["PolicyArn"])
            iam.delete_role(RoleName=role)
            ok(f"Deleted IAM role: {role}")
        except Exception:
            pass

    # Security groups (must delete before VPCs)
    sgs = ec2.describe_security_groups(Filters=tag_filter())["SecurityGroups"]
    for sg in sgs:
        if sg["GroupName"] == "default":
            continue
        try:
            ec2.delete_security_group(GroupId=sg["GroupId"])
            ok(f"Deleted SG: {sg['GroupId']} ({sg['GroupName']})")
        except Exception as e:
            log(f"Could not delete SG {sg['GroupId']}: {e}")

    # NACLs
    nacls = ec2.describe_network_acls(Filters=tag_filter())["NetworkAcls"]
    for nacl in nacls:
        if nacl["IsDefault"]:
            continue
        try:
            ec2.delete_network_acl(NetworkAclId=nacl["NetworkAclId"])
            ok(f"Deleted NACL: {nacl['NetworkAclId']}")
        except Exception as e:
            log(f"Could not delete NACL {nacl['NetworkAclId']}: {e}")

    # Subnets
    subnets = ec2.describe_subnets(Filters=tag_filter())["Subnets"]
    for subnet in subnets:
        try:
            ec2.delete_subnet(SubnetId=subnet["SubnetId"])
            ok(f"Deleted subnet: {subnet['SubnetId']}")
        except Exception as e:
            log(f"Could not delete subnet {subnet['SubnetId']}: {e}")

    # VPCs
    vpcs = ec2.describe_vpcs(Filters=tag_filter())["Vpcs"]
    for vpc in vpcs:
        try:
            ec2.delete_vpc(VpcId=vpc["VpcId"])
            ok(f"Deleted VPC: {vpc['VpcId']}")
        except Exception as e:
            log(f"Could not delete VPC {vpc['VpcId']}: {e}")

    ok("Cleanup complete")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Create or destroy compliance dummy data")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--destroy", action="store_true",
                        help="Remove all dummy resources instead of creating them")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]

    print(f"\n{'='*56}")
    print(f"  Compliance dummy data - {'DESTROY' if args.destroy else 'CREATE'}")
    print(f"  account : {account_id}")
    print(f"  region  : {args.region}")
    print(f"{'='*56}")

    if args.destroy:
        destroy(session, args.region)
        return

    ec2 = session.client("ec2", region_name=args.region)
    iam = session.client("iam")
    s3 = session.client("s3")
    s3_control = session.client("s3control", region_name=args.region)

    net = create_networks(ec2)
    create_nacls(ec2, net)
    create_security_groups(ec2, net)
    create_iam_users(iam)
    create_iam_groups_and_roles(iam)
    create_s3_buckets(s3, s3_control, account_id, args.region)

    print(f"\n{'='*56}")
    print(f"  Done. Resources tagged with {TAG_KEY}={TAG_VALUE}")
    print(f"  Run your collectors now to capture evidence.")
    print(f"  To clean up: python setup_dummy_data.py --destroy")
    print(f"{'='*56}\n")

    print("  Intentional findings created:")
    print("    ✗  alice-no-mfa and bob-no-mfa - console users without MFA")
    print("    ✗  svc-dual-keys - two active access keys")
    print("    ✗  corp-legacy-ssh-open - SSH and RDP open to 0.0.0.0/0")
    print("    ✗  corp-all-ports-internal - all ports open internally")
    print("    ✗  corp-admin-overpermissioned - AdministratorAccess role")
    print("    ✗  compliance-demo-public-* - S3 bucket with no public access block")
    print()
    print("  Good posture resources created:")
    print("    ✓  cde-vpc / corp-vpc - network separation")
    print("    ✓  cde-nacl - restrictive inbound rules")
    print("    ✓  cde-web-tier / cde-app-tier - tiered security groups")
    print("    ✓  analyst-readonly - no console, no keys")
    print("    ✓  compliance-demo-private-* - versioned, public access blocked")


if __name__ == "__main__":
    main()

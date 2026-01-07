import boto3
import json
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client
from mypy_boto3_iam.client import IAMClient
from mypy_boto3_ec2.client import EC2Client

from .logger import aws_logger
from .config import SENSITIVE_PORTS

def check_s3_public_access(s3_client: S3Client) -> list[dict]:
    """
    Checks S3 buckets for public access configurations.
    """
    findings = []
    aws_logger.info("[*] Running S3 public access checks...")
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            reasons = []

            # Check Block Public Access settings
            try:
                bpa_response = s3_client.get_public_access_block(Bucket=bucket_name)
                bpa_config = bpa_response['PublicAccessBlockConfiguration']
                if not (bpa_config['BlockPublicAcls'] and bpa_config['IgnorePublicAcls'] and \
                        bpa_config['BlockPublicPolicy'] and bpa_config['RestrictPublicBuckets']):
                    reasons.append("Block Public Access settings are not fully enabled.")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    reasons.append("Block Public Access settings are not configured.")
                else:
                    aws_logger.error(f"[ERROR] S3: Could not get public access block for {bucket_name}: {e}")

            # Check Bucket ACLs
            try:
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl_response['Grants']:
                    grantee = grant['Grantee']
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        reasons.append(f"ACL grants {grant['Permission']} to AllUsers.")
                    elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                        reasons.append(f"ACL grants {grant['Permission']} to AuthenticatedUsers.")
            except ClientError as e:
                aws_logger.error(f"[ERROR] S3: Could not get ACL for {bucket_name}: {e}")

            # Check Bucket Policy
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response['Policy'])
                for statement in policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                        reasons.append("Bucket policy allows public access.")
                        break # Found a public statement, no need to check further
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    aws_logger.error(f"[ERROR] S3: Could not get policy for {bucket_name}: {e}")

            if reasons:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource_name": bucket_name,
                    "finding": "Publicly Accessible S3 Bucket",
                    "details": "; ".join(reasons),
                    "recommendation": "Enable S3 Block Public Access settings, review bucket ACLs and policies to restrict public access."
                })
    except ClientError as e:
        aws_logger.error(f"[ERROR] S3: Could not list buckets: {e}")
    return findings

def check_s3_encryption(s3_client: S3Client) -> list[dict]:
    """
    Checks S3 buckets for server-side encryption configuration.
    """
    findings = []
    aws_logger.info("[*] Running S3 encryption checks...")
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        "resource_type": "S3 Bucket",
                        "resource_name": bucket_name,
                        "finding": "S3 Bucket Not Encrypted",
                        "details": "Server-side encryption is not enabled for this bucket.",
                        "recommendation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) for the S3 bucket."
                    })
                else:
                    aws_logger.error(f"[ERROR] S3: Could not get encryption for {bucket_name}: {e}")
    except ClientError as e:
        aws_logger.error(f"[ERROR] S3: Could not list buckets: {e}")
    return findings

def check_iam_mfa(iam_client: IAMClient) -> list[dict]:
    """
    Checks IAM users for MFA (Multi-Factor Authentication) status.
    """
    findings = []
    aws_logger.info("[*] Running IAM MFA checks...")
    try:
        response = iam_client.list_users()
        for user in response['Users']:
            user_name = user['UserName']
            mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
            if not mfa_devices['MFADevices']:
                findings.append({
                    "resource_type": "IAM User",
                    "resource_name": user_name,
                    "finding": "IAM User without MFA",
                    "details": f"IAM user '{user_name}' does not have MFA enabled.",
                    "recommendation": "Enable Multi-Factor Authentication (MFA) for the IAM user to enhance login security."
                })
    except ClientError as e:
        aws_logger.error(f"[ERROR] IAM: Could not list users or MFA devices: {e}")
    return findings

def check_security_groups_unrestricted_access(ec2_client: EC2Client) -> list[dict]:
    """
    Checks Security Groups for unrestricted inbound access (0.0.0.0/0) on sensitive ports.
    """
    findings = []
    aws_logger.info("[*] Running Security Group unrestricted access checks...")
    try:
        response = ec2_client.describe_security_groups()
        for sg in response['SecurityGroups']:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            for ip_permission in sg['IpPermissions']:
                # Check if port is sensitive and open to 0.0.0.0/0
                if ip_permission.get('FromPort') and ip_permission.get('ToPort'):
                    for port in range(ip_permission['FromPort'], ip_permission['ToPort'] + 1):
                        if port in SENSITIVE_PORTS:
                            for ip_range in ip_permission.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    findings.append({
                                        "resource_type": "Security Group",
                                        "resource_name": f"{sg_name} ({sg_id})",
                                        "finding": "Unrestricted Inbound Access on Sensitive Port",
                                        "details": f"Security Group allows unrestricted inbound access (0.0.0.0/0) on port {port} ({ip_permission.get('IpProtocol')}).",
                                        "recommendation": f"Restrict inbound access on port {port} to trusted IP addresses only. Avoid 0.0.0.0/0."
                                    })
    except ClientError as e:
        aws_logger.error(f"[ERROR] EC2: Could not describe security groups: {e}")
    return findings

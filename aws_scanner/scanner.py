import boto3
from botocore.exceptions import ClientError

from .logger import aws_logger
from .config import AWS_REGION
from .checks import (
    check_s3_public_access,
    check_s3_encryption,
    check_iam_mfa,
    check_security_groups_unrestricted_access
)

class AWSMisconfigurationScanner:
    """
    Scans an AWS account for common security misconfigurations.
    """
    def __init__(self, region_name: str = AWS_REGION):
        self.region_name = region_name
        self.findings = []
        aws_logger.info(f"[*] AWS Misconfiguration Scanner initialized for region: {self.region_name}")

    def _get_aws_clients(self):
        """
        Initializes and returns boto3 clients for necessary AWS services.
        """
        aws_logger.info("[*] Initializing AWS clients...")
        try:
            s3_client = boto3.client('s3', region_name=self.region_name)
            iam_client = boto3.client('iam', region_name=self.region_name)
            ec2_client = boto3.client('ec2', region_name=self.region_name)
            aws_logger.info("[+] AWS clients initialized.")
            return s3_client, iam_client, ec2_client
        except ClientError as e:
            aws_logger.critical(f"[CRITICAL] Failed to initialize AWS clients. Check credentials and region: {e}")
            raise

    def run_scan(self):
        """
        Executes all defined misconfiguration checks and collects findings.
        """
        aws_logger.info("[*] Starting AWS misconfiguration scan...")
        try:
            s3_client, iam_client, ec2_client = self._get_aws_clients()

            # Run S3 checks
            self.findings.extend(check_s3_public_access(s3_client))
            self.findings.extend(check_s3_encryption(s3_client))

            # Run IAM checks
            self.findings.extend(check_iam_mfa(iam_client))

            # Run EC2/Security Group checks
            self.findings.extend(check_security_groups_unrestricted_access(ec2_client))

            aws_logger.info(f"[+] Scan complete. Found {len(self.findings)} potential misconfigurations.")
            return self.findings
        except Exception as e:
            aws_logger.critical(f"[CRITICAL] An error occurred during the scan: {e}")
            raise

import unittest
from unittest.mock import patch, MagicMock
import json

from botocore.exceptions import ClientError

from aws_scanner.checks import (
    check_s3_public_access,
    check_s3_encryption,
    check_iam_mfa,
    check_security_groups_unrestricted_access
)
from aws_scanner.scanner import AWSMisconfigurationScanner
from aws_scanner.config import SENSITIVE_PORTS

class TestAWSChecks(unittest.TestCase):

    def setUp(self):
        # Mock logger
        patch('aws_scanner.checks.aws_logger').start()
        self.addCleanup(patch.stopall)

    def test_check_s3_public_access_vulnerable(self):
        mock_s3_client = MagicMock()
        mock_s3_client.list_buckets.return_value = {'Buckets': [{'Name': 'public-bucket'}]}
        # Simulate no public access block config
        mock_s3_client.get_public_access_block.side_effect = ClientError({'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration'}}, 'GetPublicAccessBlock')
        # Simulate public ACL
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}]
        }
        # Simulate public policy
        mock_s3_client.get_bucket_policy.side_effect = ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')

        findings = check_s3_public_access(mock_s3_client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Publicly Accessible S3 Bucket", findings[0]['finding'])
        self.assertIn("Block Public Access settings are not configured", findings[0]['details'])
        self.assertIn("ACL grants READ to AllUsers", findings[0]['details'])

    def test_check_s3_public_access_secure(self):
        mock_s3_client = MagicMock()
        mock_s3_client.list_buckets.return_value = {'Buckets': [{'Name': 'private-bucket'}]}
        mock_s3_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
        mock_s3_client.get_bucket_acl.return_value = {'Grants': []}
        mock_s3_client.get_bucket_policy.side_effect = ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')

        findings = check_s3_public_access(mock_s3_client)
        self.assertEqual(len(findings), 0)

    def test_check_s3_encryption_vulnerable(self):
        mock_s3_client = MagicMock()
        mock_s3_client.list_buckets.return_value = {'Buckets': [{'Name': 'unencrypted-bucket'}]}
        mock_s3_client.get_bucket_encryption.side_effect = ClientError({'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}, 'GetBucketEncryption')

        findings = check_s3_encryption(mock_s3_client)
        self.assertEqual(len(findings), 1)
        self.assertIn("S3 Bucket Not Encrypted", findings[0]['finding'])

    def test_check_s3_encryption_secure(self):
        mock_s3_client = MagicMock()
        mock_s3_client.list_buckets.return_value = {'Buckets': [{'Name': 'encrypted-bucket'}]}
        mock_s3_client.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {}}

        findings = check_s3_encryption(mock_s3_client)
        self.assertEqual(len(findings), 0)

    def test_check_iam_mfa_vulnerable(self):
        mock_iam_client = MagicMock()
        mock_iam_client.list_users.return_value = {'Users': [{'UserName': 'testuser'}]}
        mock_iam_client.list_mfa_devices.return_value = {'MFADevices': []}

        findings = check_iam_mfa(mock_iam_client)
        self.assertEqual(len(findings), 1)
        self.assertIn("IAM User without MFA", findings[0]['finding'])

    def test_check_iam_mfa_secure(self):
        mock_iam_client = MagicMock()
        mock_iam_client.list_users.return_value = {'Users': [{'UserName': 'testuser'}]}
        mock_iam_client.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': 'arn:aws:iam::123456789012:mfa/testuser'}]}

        findings = check_iam_mfa(mock_iam_client)
        self.assertEqual(len(findings), 0)

    def test_check_security_groups_unrestricted_access_vulnerable(self):
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'GroupId': 'sg-123',
                'GroupName': 'public-ssh',
                'IpPermissions': [{
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            }]
        }

        findings = check_security_groups_unrestricted_access(mock_ec2_client)
        self.assertEqual(len(findings), 1)
        self.assertIn("Unrestricted Inbound Access on Sensitive Port", findings[0]['finding'])
        self.assertIn("port 22", findings[0]['details'])

    def test_check_security_groups_unrestricted_access_secure(self):
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'GroupId': 'sg-123',
                'GroupName': 'private-ssh',
                'IpPermissions': [{
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '1.2.3.4/32'}]
                }]
            }]
        }

        findings = check_security_groups_unrestricted_access(mock_ec2_client)
        self.assertEqual(len(findings), 0)

class TestAWSMisconfigurationScanner(unittest.TestCase):

    def setUp(self):
        self.region = "us-east-1"
        self.scanner = AWSMisconfigurationScanner(region_name=self.region)
        # Mock logger
        patch('aws_scanner.scanner.aws_logger').start()
        self.addCleanup(patch.stopall)

    @patch('boto3.client')
    @patch('aws_scanner.scanner.check_s3_public_access', return_value=[{'finding': 'S3 Public'}])
    @patch('aws_scanner.scanner.check_s3_encryption', return_value=[{'finding': 'S3 Unencrypted'}])
    @patch('aws_scanner.scanner.check_iam_mfa', return_value=[{'finding': 'IAM No MFA'}])
    @patch('aws_scanner.scanner.check_security_groups_unrestricted_access', return_value=[{'finding': 'SG Unrestricted'}])
    def test_run_scan_success(self, mock_sg_check, mock_iam_check, mock_s3_enc_check, mock_s3_public_check, mock_boto_client):
        mock_boto_client.side_effect = [MagicMock(), MagicMock(), MagicMock()] # s3, iam, ec2 clients

        findings = self.scanner.run_scan()

        self.assertEqual(len(findings), 4)
        self.assertTrue(any(f['finding'] == 'S3 Public' for f in findings))
        self.assertTrue(any(f['finding'] == 'S3 Unencrypted' for f in findings))
        self.assertTrue(any(f['finding'] == 'IAM No MFA' for f in findings))
        self.assertTrue(any(f['finding'] == 'SG Unrestricted' for f in findings))

        mock_s3_public_check.assert_called_once()
        mock_s3_enc_check.assert_called_once()
        mock_iam_check.assert_called_once()
        mock_sg_check.assert_called_once()

    @patch('boto3.client', side_effect=ClientError({'Error': {'Code': 'AuthFailure'}}, 'AssumeRole'))
    def test_run_scan_auth_failure(self, mock_boto_client):
        with self.assertRaises(ClientError):
            self.scanner.run_scan()

if __name__ == '__main__':
    unittest.main()

import unittest
import json
from aws_scanner.reporter import generate_report

class TestReporter(unittest.TestCase):

    def setUp(self):
        self.findings = [
            {
                "resource_type": "S3 Bucket",
                "resource_name": "my-test-bucket",
                "finding": "Publicly Accessible S3 Bucket",
                "details": "ACL grants READ to AllUsers.",
                "recommendation": "Enable S3 Block Public Access settings."
            },
            {
                "resource_type": "IAM User",
                "resource_name": "test-user",
                "finding": "IAM User without MFA",
                "details": "IAM user 'test-user' does not have MFA enabled.",
                "recommendation": "Enable Multi-Factor Authentication (MFA)."
            }
        ]

    def test_generate_report_json_output(self):
        """
        Test that the report is correctly formatted as JSON.
        """
        report = generate_report(self.findings, output_format="json")
        
        # Check if the output is a valid JSON string
        try:
            data = json.loads(report)
        except json.JSONDecodeError:
            self.fail("generate_report did not produce a valid JSON string.")
        
        # Verify the structure and content of the JSON output
        self.assertEqual(len(data), len(self.findings))
        self.assertEqual(data[0]['resource_name'], self.findings[0]['resource_name'])
        self.assertEqual(data[1]['finding'], self.findings[1]['finding'])

    def test_generate_report_console_output(self):
        """
        Test that the console output is generated as expected.
        """
        report = generate_report(self.findings, output_format="console")
        
        # Check for key elements in the console report
        self.assertIn("--- AWS Misconfiguration Scan Report ---", report)
        self.assertIn(f"Total findings: {len(self.findings)}", report)
        self.assertIn("Finding 1:", report)
        self.assertIn("Finding 2:", report)
        self.assertIn(self.findings[0]['resource_name'], report)
        self.assertIn(self.findings[1]['resource_name'], report)
        self.assertIn("--- End of Report ---", report)

    def test_generate_report_no_findings(self):
        """
        Test the report output when no findings are present.
        """
        report_console = generate_report([], output_format="console")
        self.assertIn("No misconfigurations found", report_console)
        
        report_json = generate_report([], output_format="json")
        self.assertEqual(report_json, "[]")

if __name__ == '__main__':
    unittest.main()

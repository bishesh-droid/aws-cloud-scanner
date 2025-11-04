# AWS Cloud Misconfiguration Scanner

This project implements a command-line interface (CLI) tool to scan an AWS account for common security misconfigurations. It leverages the `boto3` SDK to interact with AWS services, inspects resource configurations against security best practices, and generates a report of potential vulnerabilities. This tool is designed for educational purposes to highlight common cloud security pitfalls.

## Features

-   **AWS Integration:** Connects to your AWS account using `boto3`.
-   **S3 Bucket Checks:** Identifies publicly accessible S3 buckets and those without server-side encryption.
-   **IAM User Checks:** Flags IAM users without Multi-Factor Authentication (MFA) enabled.
-   **Security Group Checks:** Detects security groups allowing unrestricted inbound access (0.0.0.0/0) on sensitive ports (e.g., SSH, RDP, database ports).
-   **Detailed Reporting:** Generates a human-readable report (console or JSON format) of all findings, including affected resources, misconfiguration details, and actionable recommendations.
-   **Configurable Region:** Allows specifying the AWS region to scan.
-   **Logging:** Records all scan activities and findings.

## Project Structure

```
.
├── aws_scanner/
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface using Click
│   ├── scanner.py         # Orchestrates the misconfiguration checks
│   ├── checks.py          # Contains individual misconfiguration check functions
│   ├── reporter.py        # Generates scan reports
│   ├── logger.py          # Configures logging for the scanner
│   └── config.py          # Configuration for AWS region, sensitive ports, etc.
├── logs/
│   └── aws_scanner.log    # Log file for scan activities
├── tests/
│   ├── __init__.py
│   └── test_scanner.py    # Unit tests for checks and scanner logic (mocking boto3)
├── .env.example           # Example environment variables for AWS credentials
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies
-   **AWS Account:** An active AWS account.
-   **AWS Credentials:** Configured AWS credentials with **read-only permissions** for the services being scanned (S3, IAM, EC2). You can configure these via:
    -   Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
    -   AWS CLI configuration file (`~/.aws/credentials`).
    -   IAM roles (if running on an EC2 instance or Lambda).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/AWS-Misconfiguration-Scanner.git
    cd AWS-Misconfiguration-Scanner
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure AWS Credentials:**
    Ensure your AWS credentials are set up with read-only access to S3, IAM, and EC2 services. For example, by setting environment variables:
    ```bash
    export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
    # export AWS_SESSION_TOKEN="YOUR_SESSION_TOKEN" (if using temporary credentials)
    ```

## Usage

Run the AWS Misconfiguration Scanner from the project root directory.

```bash
python -m aws_scanner.cli scan
```

**Examples:**

-   **Run a scan in the default region (us-east-1):**
    ```bash
    python -m aws_scanner.cli scan
    ```

-   **Scan a specific AWS region (e.g., eu-west-1):**
    ```bash
    python -m aws_scanner.cli scan -r eu-west-1
    ```

-   **Generate a JSON report and save it to a file:**
    ```bash
    python -m aws_scanner.cli scan -f json -o aws_security_report.json
    ```

**Important Notes:**

-   **Permissions:** The tool requires appropriate AWS IAM permissions to list and describe resources. Ensure the credentials used have at least `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetPublicAccessBlock`, `s3:GetBucketEncryption`, `iam:ListUsers`, `iam:ListMFADevices`, `ec2:DescribeSecurityGroups`.
-   **Read-Only:** This tool is designed to be read-only and does not make any changes to your AWS environment.

## Ethical Considerations

-   **Authorization:** Only scan AWS accounts you own or have explicit permission to audit. Unauthorized scanning is a violation of AWS's Acceptable Use Policy.
-   **Cost:** While listing resources is generally low-cost, be aware of potential API call charges if running very extensive scans.
-   **Educational Purpose:** This tool is for educational and research purposes. It is a simplified scanner and should not be used as a substitute for commercial, production-grade Cloud Security Posture Management (CSPM) solutions.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
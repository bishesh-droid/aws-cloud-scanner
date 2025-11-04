# aws_scanner/config.py

import os

# Default AWS region to scan.
# Can be overridden via CLI option or AWS environment variables/config.
AWS_REGION = "us-east-1"

# List of sensitive ports that should not be open to the internet (0.0.0.0/0).
# Common examples include SSH, RDP, database ports, etc.
SENSITIVE_PORTS = [
    22,   # SSH
    23,   # Telnet
    3389, # RDP
    21,   # FTP
    25,   # SMTP
    110,  # POP3
    143,  # IMAP
    3306, # MySQL
    5432, # PostgreSQL
    1521, # Oracle
    27017 # MongoDB
]

# Path for the AWS Scanner log file
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'aws_scanner.log')

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True

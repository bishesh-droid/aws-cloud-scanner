import click
import sys

from .scanner import AWSMisconfigurationScanner
from .reporter import generate_report
from .logger import aws_logger
from .config import AWS_REGION

@click.group()
def cli():
    """
    AWS Cloud Misconfiguration Scanner CLI.
    Scans an AWS account for common security misconfigurations.
    """
    pass

@cli.command()
@click.option('--region', '-r', default=AWS_REGION,
              help=f'AWS region to scan (default: {AWS_REGION}).')
@click.option('--output-format', '-f', type=click.Choice(['console', 'json'], case_sensitive=False),
              default='console', help='Output format for the report.')
@click.option('--output-file', '-o', type=click.Path(),
              help='Save report to a file (e.g., report.json or report.txt).')
def scan(region, output_format, output_file):
    """
    Runs the AWS misconfiguration scan.
    """
    aws_logger.info(f"[*] Starting AWS misconfiguration scan in region: {region}")

    scanner = AWSMisconfigurationScanner(region_name=region)

    try:
        findings = scanner.run_scan()
        report = generate_report(findings, output_format)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                click.echo(f"\n[*] Report saved to: {output_file}")
            except IOError as e:
                aws_logger.error(f"Error: Could not write report to file {output_file}: {e}")
        else:
            click.echo(report)

    except Exception as e:
        aws_logger.critical(f"[CRITICAL] Scan failed: {e}")
        click.echo(f"Error: Scan failed: {e}", err=True)
        sys.exit(1)

    aws_logger.info("[*] AWS misconfiguration scan finished.")

if __name__ == '__main__':
    cli()

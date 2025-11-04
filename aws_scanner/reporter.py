import json

def generate_report(findings: list[dict], output_format: str = "console") -> str:
    """
    Generates a human-readable report from the scan findings.

    Args:
        findings (list): A list of dictionaries, each representing a misconfiguration finding.
        output_format (str): The desired output format ('console' or 'json').

    Returns:
        str: The formatted report string.
    """
    if output_format == "json":
        return json.dumps(findings, indent=4)
    else:
        report_lines = []
        report_lines.append("\n--- AWS Misconfiguration Scan Report ---")
        report_lines.append(f"Total findings: {len(findings)}")
        report_lines.append("----------------------------------------")

        if not findings:
            report_lines.append("No misconfigurations found. Your AWS environment appears secure (based on checks performed).")
        else:
            for i, finding in enumerate(findings):
                report_lines.append(f"\nFinding {i+1}:")
                report_lines.append(f"  Resource Type: {finding.get('resource_type', 'N/A')}")
                report_lines.append(f"  Resource Name: {finding.get('resource_name', 'N/A')}")
                report_lines.append(f"  Misconfiguration: {finding.get('finding', 'N/A')}")
                report_lines.append(f"  Details: {finding.get('details', 'N/A')}")
                report_lines.append(f"  Recommendation: {finding.get('recommendation', 'N/A')}")

        report_lines.append("\n--- End of Report ---")
        return "\n".join(report_lines)

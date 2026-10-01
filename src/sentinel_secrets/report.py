import json

from .scanner import Finding

def format_console(findings: list[Finding]) -> str:
    if not findings:
        return 'No findings.'

    header = f"{'SEVERITY':<10} {'RULE':<25} {'SOURCE':<30} {'LINE':<6} {'MATCHED'}"

    rows = [
        f"{finding.severity.value:<10} "
        f"{finding.rule_name:<25} "
        f"{finding.source:<30} "
        f"{finding.line_number:<6} "
        f"{finding.matched_text}"
        for finding in findings
    ]

    return '\n'.join([header] + rows)

def format_json(findings: list[Finding]) -> str:
    data = [
        {
            "source": finding.source,
            "line_number": finding.line_number,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
            "matched_text": finding.matched_text,
        }
        for finding in findings
    ]

    return json.dumps(data, indent=2)

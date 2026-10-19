import json

from .scanner import Finding

def format_console(findings: list[Finding]) -> str:
    if not findings:
        return 'No findings.'

    # Widen RULE and SOURCE to their longest value so long rule names and
    # paths can't push the later columns out of line.
    rule_width = max(25, *(len(finding.rule_name) for finding in findings))
    source_width = max(30, *(len(finding.source) for finding in findings))

    header = (
        f"{'SEVERITY':<10} {'RULE':<{rule_width}} "
        f"{'SOURCE':<{source_width}} {'LINE':<6} {'MATCHED'}"
    )

    rows = [
        f"{finding.severity.value:<10} "
        f"{finding.rule_name:<{rule_width}} "
        f"{finding.source:<{source_width}} "
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

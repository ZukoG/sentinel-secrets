import json

from sentinel_secrets.scanner import Finding, scan_content
from sentinel_secrets.patterns import Severity
from sentinel_secrets.report import format_console, format_json


def make_finding() -> Finding:
    return Finding(
        source="config.py",
        line_number=10,
        rule_name="AWS Access Key ID",
        severity=Severity.HIGH,
        matched_text="AKIA1234...",
    )


def test_format_console_empty_findings():
    assert format_console([]) == "No findings."


def test_format_console_contains_finding_fields():
    finding = make_finding()

    output = format_console([finding])

    assert "AWS Access Key ID" in output
    assert "config.py" in output
    assert "AKIA1234..." in output


def test_format_console_preserves_redaction():
    full_secret = "AKIA1234567890ABCDEF"
    content = f"AWS_ACCESS_KEY_ID={full_secret}"

    findings = scan_content(content, "config.py")

    output = format_console(findings)

    assert full_secret not in output
    assert "AKIA12..." in output


def test_format_json_contains_expected_fields_and_types():
    finding = make_finding()

    output = format_json([finding])
    data = json.loads(output)

    assert len(data) == 1

    result = data[0]

    assert result["source"] == "config.py"
    assert result["line_number"] == 10
    assert result["rule_name"] == "AWS Access Key ID"
    assert result["severity"] == "HIGH"
    assert isinstance(result["severity"], str)
    assert result["matched_text"] == "AKIA1234..."


def test_format_json_empty_findings():
    output = format_json([])

    assert json.loads(output) == []

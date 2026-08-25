from sentinel_secrets.scanner import scan_content, Finding

def test_secret_on_third_line_has_correct_line_number() -> None:
    text = (
        "This is a clean line.\n"
        "This line is also clean.\n"
        "token = ghp_" + "a" * 36 + "\n"
        "Another clean line."
    )

    findings = scan_content(text)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_known_secret_is_not_double_reported_as_high_entropy() -> None:
    github_token = "ghp_" + "a" * 36
    text = f"token = {github_token}"

    findings = scan_content(text)

    assert len(findings) == 1
    assert findings[0].rule_name == "GitHub Token"


def test_multiple_secrets_on_different_lines() -> None:
    text = (
        "aws_key = AKIAIOSFODNN7PUEXAMPLE\n"
        "github_token = " + "ghp_" + "a" * 36 + "\n"
        "-----BEGIN RSA PRIVATE KEY-----"
    )

    findings = scan_content(text)

    assert len(findings) == 3

    rule_names = [finding.rule_name for finding in findings]

    assert "AWS Access Key ID" in rule_names
    assert "GitHub Token" in rule_names
    assert "Private Key Header" in rule_names


def test_clean_content_returns_no_findings() -> None:
    text = (
        "This is ordinary application code.\n"
        "There are no secrets in this file.\n"
        "Everything here is safe."
    )

    assert scan_content(text) == []


def test_source_is_propagated_to_findings() -> None:
    text = "aws_key = AKIAIOSFODNN7PUEXAMPLE"

    findings = scan_content(text, source="myfile.py")

    assert findings
    assert all(finding.source == "myfile.py" for finding in findings)


def test_matched_secret_is_truncated() -> None:
    secret = "AKIAIOSFODNN7PUEXAMPLE"
    text = f"aws_key = {secret}"

    findings = scan_content(text)

    assert len(findings) == 1

    matched_text = findings[0].matched_text

    assert len(matched_text) < len(secret)
    assert matched_text.endswith("...")

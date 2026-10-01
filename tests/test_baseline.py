from sentinel_secrets.scanner import Finding
from sentinel_secrets.patterns import Severity
from sentinel_secrets.baseline import (
    fingerprint,
    load_baseline,
    save_baseline,
    filter_findings,
)


def make_finding(
    source: str,
    rule_name: str,
    matched_text: str,
) -> Finding:
    return Finding(
        source=source,
        line_number=10,
        rule_name=rule_name,
        severity=Severity.HIGH,
        matched_text=matched_text,
    )


def test_fingerprint_is_stable():
    finding = make_finding(
        "config.py",
        "aws-access-key",
        "AKIA...",
    )

    assert fingerprint(finding) == fingerprint(finding)


def test_different_findings_have_different_fingerprints():
    finding_one = make_finding(
        "config.py",
        "aws-access-key",
        "AKIA...",
    )

    finding_two = make_finding(
        "settings.py",
        "github-token",
        "ghp_...",
    )

    assert fingerprint(finding_one) != fingerprint(finding_two)


def test_load_baseline_missing_file_returns_empty_set(tmp_path):
    path = tmp_path / "does_not_exist.json"

    assert load_baseline(str(path)) == set()


def test_save_and_load_baseline_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    fingerprints = {"abc", "def"}

    save_baseline(str(path), fingerprints)

    assert load_baseline(str(path)) == fingerprints


def test_filter_findings_removes_known_findings():
    finding_one = make_finding(
        "config.py",
        "aws-access-key",
        "AKIA...",
    )

    finding_two = make_finding(
        "settings.py",
        "github-token",
        "ghp_...",
    )

    baseline = {fingerprint(finding_one)}

    result = filter_findings(
        [finding_one, finding_two],
        baseline,
    )

    assert result == [finding_two]

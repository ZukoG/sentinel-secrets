"""Baselines: remember known findings so later scans can leave them out."""

import  hashlib
import json

from .scanner import Finding

def fingerprint(finding : Finding) -> str:
    """Return a SHA-256 fingerprint that identifies a finding.

    The baseline file stores these hashes instead of the findings, so it
    never contains the secrets themselves.
    """
    value = f'{finding.source} | {finding.rule_name} | {finding.matched_text}'
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def load_baseline(path: str) -> set[str]:
    """Read the fingerprints in a baseline file. A missing file means an empty baseline."""
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return set(json.load(file))
    except FileNotFoundError:
        return set()

def save_baseline(path: str, fingerprints: set[str]) -> None:
    """Write fingerprints to a baseline file, sorted so changes are easy to review."""
    with open(path, 'w', encoding='utf-8') as file:
        json.dump(sorted(fingerprints), file, indent=2)

def filter_findings(
    findings: list[Finding],
    baseline: set[str],
) -> list[Finding]:
    """Return only the findings whose fingerprint is not in the baseline."""
    return [
        finding for finding in findings if fingerprint(finding) not in baseline
    ]

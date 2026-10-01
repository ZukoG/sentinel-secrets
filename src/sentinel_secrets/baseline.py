import  hashlib
import json

from .scanner import Finding

def fingerprint(finding : Finding) -> str:
    value = f'{finding.source} | {finding.rule_name} | {finding.matched_text}'
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def load_baseline(path: str) -> set[str]:
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return set(json.load(file))
    except FileNotFoundError:
        return set()

def save_baseline(path: str, fingerprints: set[str]) -> None:
    with open(path, 'w', encoding='utf-8') as file:
        json.dump(sorted(fingerprints), file, indent=2)

def filter_findings(
    findings: list[Finding],
    baseline: set[str],
) -> list[Finding]:
    return [
        finding for finding in findings if fingerprint(finding) not in baseline
    ]

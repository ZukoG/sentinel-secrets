import re
from dataclasses import dataclass

from .patterns import SIGNATURES, Severity
from .entropy import is_high_entropy

def _truncate(value: str, keep: int = 6) -> str:
    if len(value) <= keep:
        return value
    return value[:keep] + "..."

def _extract_tokens(line: str) -> list[str]:
    # "." and "$" split dotted identifiers and shell variables into words.
    # "/" is deliberately not a separator: base64 secrets (e.g. AWS secret
    # access keys) contain it and would fall apart into short pieces.
    tokens = re.split(r"[\s'\"=:,;()\[\]{}.$]+", line)

    return [token for token in tokens if token]


@dataclass(frozen=True)
class Finding:
    source: str
    line_number: int
    rule_name: str
    severity: Severity
    matched_text: str


def scan_content(
    text: str,
    source: str = '<unknown>',
) -> list[Finding]:
    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        signature_matches: list[str] = []
        reported_spans: list[tuple[int, int]] = []

        # First detect known secret patterns. SIGNATURES runs from most specific
        # to most generic, so a later match overlapping an earlier one is the
        # same secret and is skipped.
        for signature in SIGNATURES:
            for match in signature.regex.finditer(line):
                matched_text = match.group(0)
                signature_matches.append(matched_text)

                start, end = match.span()
                if any(
                    start < other_end and other_start < end
                    for other_start, other_end in reported_spans
                ):
                    continue

                reported_spans.append((start, end))

                findings.append(
                    Finding(
                        source=source,
                        line_number=line_number,
                        rule_name=signature.name,
                        severity=signature.severity,
                        matched_text=_truncate(matched_text),
                    )
                )

        # Then check remaining tokens for high entropy.
        for token in _extract_tokens(line):
            if any(token in matched_text for matched_text in signature_matches):
                continue

            if is_high_entropy(token):
                findings.append(
                    Finding(
                        source=source,
                        line_number=line_number,
                        rule_name='High Entropy String',
                        severity=Severity.MEDIUM,
                        matched_text=_truncate(token),
                    )
                )
    return findings

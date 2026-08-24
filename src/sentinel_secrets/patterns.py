import re
from enum import Enum
from dataclasses import dataclass

class Severity(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

@dataclass(frozen=True)
class Signature:
    name: str
    regex: re.Pattern
    severity: Severity
    description: str

SIGNATURES: list[Signature] = [
    Signature(
        name='AWS Access Key ID',
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.HIGH,
        description='Fixed, unmistakable prefix: real key IDs always start AKIA followed by exactly 16 uppercase alphanumerics'
    ),

    Signature(
        name='GitHub Token',
        regex=re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
        severity=Severity.HIGH,
        description='Covers personal (ghp_), OAuth (gho_), user-to-server (ghu_), server-to-server (ghs_), and refresh (ghr_) tokens — all 36 chars after the prefix'
    ),

    Signature(
            name='Slack Token',
            regex=re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
            severity=Severity.HIGH,
            description="Slack's own documented token format across bot/app/user token subtypes"
    ),

    Signature(
            name='Private Key Header',
            regex=re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            severity=Severity.CRITICAL,
            description='Presence alone means a private key is sitting in the repo; worst-case severity, no ambiguity'
        ),

    Signature(
            name='Generic Secret Assignment',
            regex=re.compile(r"""(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]"""),
            severity=Severity.MEDIUM,
            description="Catches named-but-unrecognized secrets (e.g. api_key = '...'), lower severity than the others because it's pattern-shaped guessing, not a confirmed format, so it's more prone to false positives"
        )
]

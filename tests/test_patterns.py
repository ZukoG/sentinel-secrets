import re
import pytest

from sentinel_secrets.patterns import SIGNATURES, Signature

def _signature(name: str) -> Signature:
    return next(s for s in SIGNATURES if s.name == name)

@pytest.mark.parametrize(
    "signature_name,text",
    [
        ("AWS Access Key ID", "aws_key = AKIAIOSFODNN7PUEXAMPLE"),
        ("GitHub Token", "token: " + "ghp_" + "a" * 36),
        ("Slack Token", "xoxb-1234567890abcdef"),
        ("Private Key Header", "-----BEGIN RSA PRIVATE KEY-----"),
        ("Generic Secret Assignment", 'api_key = "abcdefghijklmnopqrstuvwx"'),
    ],
)

def test_signatures_match_real_examples(signature_name: str, text: str) -> None:
    signature = _signature(signature_name)

    assert signature.regex.search(text) is not None


@pytest.mark.parametrize(
    "signature_name,text",
    [
        ("AWS Access Key ID", "this sentence has no key in it"),
        ("GitHub Token", "ghp_tooshort"),
        ("Slack Token", "xoxb-short"),
        ("Private Key Header", "-----BEGIN RSA KEY-----"),
        ("Generic Secret Assignment", 'api_key = "short"'),
    ],
)
def test_signatures_do_not_match_invalid_examples(
    signature_name: str,
    text: str,
) -> None:
    signature = _signature(signature_name)

    assert signature.regex.search(text) is None


def test_signatures_are_compiled_patterns() -> None:
    assert SIGNATURES

    for signature in SIGNATURES:
        assert isinstance(signature.regex, re.Pattern)

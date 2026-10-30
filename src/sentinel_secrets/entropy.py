"""Shannon entropy: a measure of how random a string looks, used to spot unlabeled secrets."""

import math
import collections

def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy of a string, in bits per character.

    Repetitive or predictable text scores low and random keys score high.
    An empty string scores 0.
    """
    if not s:
        return 0.0

    counts = collections.Counter(s)
    length = len(s)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(
    s: str,
    threshold: float = 4.5,
    min_length: int = 20,
) -> bool:
    """Return True if a string is long enough and random enough to look like a secret.

    By default that means at least 20 characters and more than 4.5 bits per
    character.
    """
    return len(s) >= min_length and shannon_entropy(s) > threshold

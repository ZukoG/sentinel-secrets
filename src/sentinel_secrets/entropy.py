import math
import collections

def shannon_entropy(s: str) -> float:
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
    return len(s) >= min_length and shannon_entropy(s) > threshold

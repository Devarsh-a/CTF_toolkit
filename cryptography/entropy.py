# entropy.py
import math
from collections import Counter
import string

def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte string."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def is_mostly_printable(text: str, threshold: float = 0.95) -> bool:
    """Check if the string is mostly printable ASCII characters."""
    if not text:
        return False
    printable_count = sum(c in string.printable for c in text)
    return printable_count / len(text) >= threshold

def alphabetic_ratio(text: str) -> float:
    """Return the fraction of alphabetic characters."""
    if not text:
        return 0.0
    alpha_count = sum(c.isalpha() for c in text)
    return alpha_count / len(text)

def space_ratio(text: str) -> float:
    """Return the fraction of spaces in the text."""
    if not text:
        return 0.0
    return text.count(" ") / len(text)
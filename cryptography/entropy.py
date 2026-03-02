import math
from collections import Counter

def shannon_entropy(data: bytes):
    if not data:
        return 0

    freq = Counter(data)
    length = len(data)

    return -sum(
        (count/length) * math.log2(count/length)
        for count in freq.values()
    )
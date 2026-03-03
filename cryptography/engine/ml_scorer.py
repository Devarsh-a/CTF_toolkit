# ml_scorer.py
import string
from collections import Counter
from entropy import shannon_entropy, is_mostly_printable, alphabetic_ratio, space_ratio

# English letter frequency for scoring
ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51,
    'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09,
    'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23,
    'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
    'V': 0.98, 'K': 0.77, 'X': 0.15, 'J': 0.15,
    'Q': 0.10, 'Z': 0.07
}

COMMON_WORDS = ["the", "and", "that", "have", "for", "with", "flag", "http", "https"]

class PlaintextScorer:
    """Combine heuristics and statistics into a single plaintext score."""

    def __init__(self):
        pass

    def score(self, data) -> float:
        if not data:
            return 0.0

        # Decode bytes if necessary
        if isinstance(data, bytes):
            try:
                data = data.decode(errors="ignore")
            except:
                return 0.0

        score = 0.0

        # ------------------------
        # 1️⃣ Printable ratio
        # ------------------------
        score += is_mostly_printable(data) * 1.0

        # ------------------------
        # 2️⃣ Shannon entropy
        # ------------------------
        entropy_val = shannon_entropy(data.encode())
        score += 1 - abs(entropy_val - 4.2) / 4.2  # English ≈ 3.5–4.5

        # ------------------------
        # 3️⃣ Alphabetic & space ratios
        # ------------------------
        score += alphabetic_ratio(data)
        score += space_ratio(data)

        # ------------------------
        # 4️⃣ English letter frequency match
        # ------------------------
        letters = [c.upper() for c in data if c in string.ascii_letters]
        if letters:
            freq = Counter(letters)
            total = sum(freq.values())
            freq_score = 0.0
            for letter in ENGLISH_FREQ:
                observed = (freq.get(letter, 0) / total) * 100
                expected = ENGLISH_FREQ[letter]
                freq_score += 1 - abs(observed - expected) / expected
            score += freq_score / len(ENGLISH_FREQ)

        # ------------------------
        # 5️⃣ Common word bonus
        # ------------------------
        lower = data.lower()
        for word in COMMON_WORDS:
            if word in lower:
                score += 0.5

        return score
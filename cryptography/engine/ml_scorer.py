import math
import string
from collections import Counter



# Character Frequency Model (English baseline)


ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51,
    'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09,
    'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23,
    'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
    'V': 0.98, 'K': 0.77, 'X': 0.15, 'J': 0.15,
    'Q': 0.10, 'Z': 0.07
}
common_words = [" the ", " and ", " attack ", " at ", " dawn ", "flag"," ctf ", " key ", " secret "]


# Core ML Scorer


class PlaintextScorer:

    def __init__(self):
        pass

    
    # 1️⃣ Printable Ratio
    
    def printable_score(self, text):
        if not text:
            return 0
        printable = sum(c in string.printable for c in text)
        return printable / len(text)

    
    # 2️⃣ Entropy Score
    
    def entropy_score(self, text):
        if not text:
            return 0

        freq = Counter(text)
        length = len(text)

        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

        # English text entropy ≈ 3.5–4.5
        # Random ≈ 7–8
        return 1 - abs(entropy - 4.2) / 4.2

    
    # 3️⃣ English Frequency Match
    
    def english_score(self, text):
        if not text:
            return 0

        text = text.upper()
        letters = [c for c in text if c in ENGLISH_FREQ]

        if not letters:
            return 0

        freq = Counter(letters)
        total = sum(freq.values())

        score = 0
        for letter in ENGLISH_FREQ:
            observed = (freq.get(letter, 0) / total) * 100
            expected = ENGLISH_FREQ[letter]
            score += 1 - abs(observed - expected) / expected

        return score / len(ENGLISH_FREQ)

    
    # 4️⃣ Structural Pattern Bonus
    
    def structural_score(self, text):
        bonus = 0

        if "{" in text and "}" in text:
            bonus += 0.1
        if ":" in text:
            bonus += 0.05
        if "http" in text:
            bonus += 0.1
        if "flag" in text.lower():
            bonus += 0.2
        if "\n" in text:
            bonus += 0.05

        return min(bonus, 0.3)

    
    # Final Score
    
   
    def score(self, data) -> float:
        if not data:
            return 0.0

        # Accept both bytes and str
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8", errors="ignore")
            except:
                return 0.0
        else:
            text = data

        if not text:
            return 0.0

        score = 0.0

        # Core statistical signals
        score += 0.30 * self.printable_score(text)
        score += 0.25 * self.entropy_score(text)
        score += 0.30 * self.english_score(text)
        score += 0.15 * self.structural_score(text)

        # Small English word boost (helps XOR)
        
        lower = text.lower()
        for word in common_words:
            if word in lower:
                score += 0.3

        return score
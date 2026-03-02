import string
from collections import Counter

COMMON_WORDS = [
    "the", "and", "flag", "ctf", "crypto",
    "password", "admin", "key", "secret"
]

ETAOIN = "etaoinshrdlu"

def english_score(data: bytes):
    try:
        text = data.decode(errors="ignore").lower()
    except:
        return -9999

    if len(text) == 0:
        return -9999

    printable_ratio = sum(c in string.printable for c in text) / len(text)
    word_bonus = sum(word in text for word in COMMON_WORDS)

    letters = Counter(c for c in text if c.isalpha())
    total_letters = sum(letters.values())

    if total_letters == 0:
        return -9999

    freq_score = sum(
        (letters.get(c, 0) / total_letters)
        for c in ETAOIN
    )

    return printable_ratio + word_bonus + freq_score
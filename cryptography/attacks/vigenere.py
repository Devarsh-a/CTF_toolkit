# attacks/vigenere.py
from collections import Counter
import string

# -----------------------
# Classic Vigenère (letters only)
# -----------------------

def _key_to_shifts(key: bytes):
    """Convert ASCII key to 0-25 shifts (case-insensitive)."""
    shifts = []
    for k in key:
        ch = chr(k).lower()
        if not ch.isalpha():
            raise ValueError("Key must be alphabetic")
        shifts.append(ord(ch) - ord("a"))
    return shifts


def vigenere_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt letters A-Z/a-z; other characters unchanged."""
    shifts = _key_to_shifts(key)
    ciphertext = bytearray()
    key_index = 0

    for b in plaintext:
        ch = chr(b)
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = shifts[key_index % len(shifts)]
            ciphertext.append((b - base + shift) % 26 + base)
            key_index += 1
        else:
            ciphertext.append(b)

    return bytes(ciphertext)


def vigenere_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt letters A-Z/a-z; other characters unchanged."""
    shifts = _key_to_shifts(key)
    plaintext = bytearray()
    key_index = 0

    for b in ciphertext:
        ch = chr(b)
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = shifts[key_index % len(shifts)]
            plaintext.append((b - base - shift) % 26 + base)
            key_index += 1
        else:
            plaintext.append(b)

    return bytes(plaintext)


# -----------------------
# Vigenère Breaker
# -----------------------

def _index_of_coincidence(text: str):
    N = len(text)
    if N <= 1:
        return 0
    freqs = Counter(text)
    return sum(f * (f - 1) for f in freqs.values()) / (N * (N - 1))


def _estimate_key_length(ciphertext: str, max_len=12):
    """Guess key length by IC"""
    best_len = 1
    best_ic = 0
    for key_len in range(1, max_len + 1):
        columns = [ciphertext[i::key_len] for i in range(key_len)]
        avg_ic = sum(_index_of_coincidence(col) for col in columns) / key_len
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = key_len
    return best_len


def _break_caesar_column(column: str):
    """Break a Caesar-shifted column"""
    best_shift = 0
    best_score = float("-inf")
    for shift in range(26):
        decrypted = ""
        for c in column:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                decrypted += chr((ord(c) - base - shift) % 26 + base)
            else:
                decrypted += c
        score = sum(ch in " ETAOINSHRDLUetaoinshrdlu" for ch in decrypted)
        if score > best_score:
            best_score = score
            best_shift = shift
    return best_shift


def break_vigenere(ciphertext: bytes, max_key_len=12):
    """Brute-force Vigenère breaker (letters only)"""
    try:
        text = ciphertext.decode("ascii")
    except:
        return None

    best_score = float("-inf")
    best_result = None

    # Try key lengths 1..max_key_len
    for key_len in range(1, max_key_len + 1):
        columns = [""] * key_len
        key_index = 0
        for c in text:
            if c.isalpha():
                columns[key_index % key_len] += c
                key_index += 1

        key = ""
        for col in columns:
            if col:
                shift = _break_caesar_column(col)
                key += chr(shift + ord("a"))
            else:
                key += "a"

        # Decrypt with candidate key
        plaintext = ""
        key_index = 0
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                shift = ord(key[key_index % key_len]) - ord("a")
                plaintext += chr((ord(c) - base - shift) % 26 + base)
                key_index += 1
            else:
                plaintext += c

        score = sum(ch in " etaoinshrdluETAOINSHRDLU" for ch in plaintext)
        if score > best_score:
            best_score = score
            best_result = {
                "key": key,
                "plaintext": plaintext.encode(),
                "score": score,
            }

    return best_result
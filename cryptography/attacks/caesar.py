# attacks/caesar.py

def increment_encrypt(data: bytes, shift: int = 1) -> bytes:
    """Encrypt data by incrementing each byte by shift (mod 256)"""
    return bytes((b + shift) % 256 for b in data)

def increment_decrypt(data: bytes, shift: int = 1) -> bytes:
    """Decrypt data by decrementing each byte by shift (mod 256)"""
    return bytes((b - shift) % 256 for b in data)

def break_caesar(ciphertext: bytes):
    """
    Brute-force all 26 Caesar shifts.
    Returns best candidate based on simple English scoring.
    """
    best_score = float("-inf")
    best_result = None

    for shift in range(26):
        plaintext = increment_decrypt(ciphertext, shift)

        try:
            text = plaintext.decode("ascii")
        except:
            continue

        score = 0

        for c in text:
            if c.isalpha():
                score += 2
            elif c == " ":
                score += 3
            elif 32 <= ord(c) <= 126:
                score += 0.2
            else:
                score -= 2

        if score > best_score:
            best_score = score
            best_result = {
                "key": shift,
                "plaintext": plaintext,
                "score": score
            }

    return best_result
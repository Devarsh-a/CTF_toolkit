# attacks/single_xor.py
def single_xor_encrypt(data: bytes, key: int) -> bytes:
    """Encrypt/decrypt data with single-byte XOR (0-255)"""
    return bytes(b ^ key for b in data)

# For XOR, encrypt = decrypt
def single_xor_decrypt(data: bytes, key: int) -> bytes:
    """Encrypt/decrypt data with single-byte XOR (0-255)"""
    return bytes(b ^ key for b in data)

def break_single_xor(ciphertext: bytes):
    """
    Brute-force single-byte XOR and return best English candidate.
    """
    best_score = float("-inf")
    best_result = None

    for key in range(256):
        plaintext = bytes(b ^ key for b in ciphertext)

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
            elif c in ".,'!?":
                score += 1
            elif 32 <= ord(c) <= 126:
                score += 0.2
            else:
                score -= 3

        # Bonus for common words
        if " the " in text:
            score += 5
        if " and " in text:
            score += 5
        if "attack" in text:
            score += 10

        if score > best_score:
            best_score = score
            best_result = {
                "key": key,
                "plaintext": plaintext,
                "score": score
            }

    return best_result
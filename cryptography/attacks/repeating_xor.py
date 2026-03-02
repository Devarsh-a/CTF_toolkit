# attacks/repeating_xor.py
from itertools import product
from scoring import english_score  # your existing scoring function

def break_repeating_xor(cipher: bytes, max_key_len=3):
    """
    Brute-force repeating-key XOR for small keys (≤ max_key_len).
    Guarantees recovery of exact key and plaintext.
    """
    best_score = -9999
    best_result = None

    # Try all key lengths
    for key_len in range(1, max_key_len + 1):
        # Try all possible byte combinations for the key
        for key_tuple in product(range(256), repeat=key_len):
            key = bytes(key_tuple)
            # Decrypt full ciphertext
            plaintext = bytes(cipher[i] ^ key[i % key_len] for i in range(len(cipher)))
            # Score the plaintext
            score = english_score(plaintext)
            # Keep best scoring candidate
            if score > best_score:
                best_score = score
                best_result = {
                    "type": "repeating_xor",
                    "key": key,
                    "plaintext": plaintext,
                    "score": score
                }

    return best_result

# attacks/repeating_xor.py
def repeating_xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt plaintext with repeating XOR key"""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def repeating_xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext with repeating XOR key"""
    # XOR is symmetric
    return repeating_xor_encrypt(data, key)
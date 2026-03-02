# attacks/substitution.py
import string

ALPHABET = string.ascii_uppercase

def substitution_encrypt(plaintext: str, key: str) -> str:
    """Substitution cipher encrypt"""
    mapping = {ALPHABET[i]: key[i] for i in range(len(ALPHABET))}
    return ''.join(mapping.get(c.upper(), c) for c in plaintext)

def substitution_decrypt(ciphertext: str, key: str) -> str:
    """Substitution cipher decrypt"""
    mapping = {key[i]: ALPHABET[i] for i in range(len(ALPHABET))}
    return ''.join(mapping.get(c.upper(), c) for c in ciphertext)
# engine.py
from attacks import (
    single_xor, repeating_xor, caesar, rot_n, playfair, vigenere,
    transposition, substitution, rc4, aes_cipher
)

# --- Map of cipher_name -> encrypt/decrypt functions ---
CIPHERS = {
    "single_xor": {"encrypt": single_xor.single_xor_encrypt, "decrypt": single_xor.single_xor_decrypt},
    "repeating_xor": {"encrypt": repeating_xor.repeating_xor_encrypt, "decrypt": repeating_xor.repeating_xor_decrypt},
    "caesar": {"encrypt": caesar.increment_encrypt, "decrypt": caesar.increment_decrypt},
    "rot": {"encrypt": rot_n.rot_encrypt, "decrypt": rot_n.rot_decrypt},
    "playfair": {"encrypt": playfair.playfair_encrypt, "decrypt": playfair.playfair_decrypt},
    "vigenere": {"encrypt": vigenere.vigenere_encrypt, "decrypt": vigenere.vigenere_decrypt},
    "transposition": {"encrypt": transposition.transposition_encrypt, "decrypt": transposition.transposition_decrypt},
    "substitution": {"encrypt": substitution.substitution_encrypt, "decrypt": substitution.substitution_decrypt},
    "rc4": {"encrypt": rc4.rc4_encrypt, "decrypt": rc4.rc4_decrypt},
    "aes_ecb": {"encrypt": aes_cipher.aes_encrypt, "decrypt": aes_cipher.aes_decrypt},
    "aes_cbc": {"encrypt": aes_cipher.aes_encrypt, "decrypt": aes_cipher.aes_decrypt},
}

def encrypt(plaintext: bytes, cipher_name: str, key: bytes = b"", **kwargs) -> bytes:
    """Encrypt plaintext with the selected cipher"""
    if cipher_name not in CIPHERS:
        raise ValueError(f"Cipher '{cipher_name}' not supported")
    return CIPHERS[cipher_name]["encrypt"](plaintext, key, **kwargs)

def decrypt(ciphertext: bytes, cipher_name: str, key: bytes = b"", **kwargs) -> bytes:
    """Decrypt ciphertext with the selected cipher"""
    if cipher_name not in CIPHERS:
        raise ValueError(f"Cipher '{cipher_name}' not supported")
    return CIPHERS[cipher_name]["decrypt"](ciphertext, key, **kwargs)
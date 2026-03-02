# attacks/vigenere.py
def vigenere_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Vigenère cipher encrypt"""
    ciphertext = bytearray()
    key_len = len(key)
    for i, b in enumerate(plaintext):
        ciphertext.append((b + key[i % key_len]) % 256)
    return bytes(ciphertext)

def vigenere_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Vigenère cipher decrypt"""
    plaintext = bytearray()
    key_len = len(key)
    for i, b in enumerate(ciphertext):
        plaintext.append((b - key[i % key_len]) % 256)
    return bytes(plaintext)
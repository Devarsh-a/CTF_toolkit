# attacks/rc4.py
def rc4_keystream(key: bytes, length: int) -> bytes:
    S = list(range(256))
    j = 0
    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    i = j = 0
    keystream = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return bytes(keystream)

def rc4_encrypt(plaintext: bytes, key: bytes) -> bytes:
    ks = rc4_keystream(key, len(plaintext))
    return bytes([b ^ k for b, k in zip(plaintext, ks)])

def rc4_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    # RC4 is symmetric
    return rc4_encrypt(ciphertext, key)
# attacks/single_xor.py
def single_xor_encrypt(data: bytes, key: int) -> bytes:
    """Encrypt/decrypt data with single-byte XOR (0-255)"""
    return bytes(b ^ key for b in data)

# For XOR, encrypt = decrypt
single_xor_decrypt = single_xor_encrypt
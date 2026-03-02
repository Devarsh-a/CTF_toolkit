# attacks/caesar.py

def increment_encrypt(data: bytes, shift: int = 1) -> bytes:
    """Encrypt data by incrementing each byte by shift (mod 256)"""
    return bytes((b + shift) % 256 for b in data)

def increment_decrypt(data: bytes, shift: int = 1) -> bytes:
    """Decrypt data by decrementing each byte by shift (mod 256)"""
    return bytes((b - shift) % 256 for b in data)
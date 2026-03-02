# attacks/rot_n.py
def rot_encrypt(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)

def rot_decrypt(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)
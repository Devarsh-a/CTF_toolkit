# attacks/aes_cipher.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext: bytes, key: bytes, mode: str = "ECB", iv: bytes = None) -> bytes:
    """
    Encrypt bytes with AES in ECB or CBC mode.
    key must be 16, 24, or 32 bytes.
    iv is required for CBC mode.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    
    plaintext_padded = pad(plaintext, AES.block_size)
    
    if mode.upper() == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode.upper() == "CBC":
        if iv is None:
            raise ValueError("CBC mode requires IV")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported AES mode")
    
    return cipher.encrypt(plaintext_padded)

def aes_decrypt(ciphertext: bytes, key: bytes, mode: str = "ECB", iv: bytes = None) -> bytes:
    """
    Decrypt bytes with AES in ECB or CBC mode.
    key must be 16, 24, or 32 bytes.
    iv is required for CBC mode.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    
    if mode.upper() == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode.upper() == "CBC":
        if iv is None:
            raise ValueError("CBC mode requires IV")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported AES mode")
    
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded, AES.block_size)
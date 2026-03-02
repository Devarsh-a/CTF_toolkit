# attacks/rsa_cipher.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def generate_rsa_keypair(bits=2048):
    """Generate RSA public/private key pair"""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext: bytes, public_key_bytes: bytes) -> bytes:
    key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher.encrypt(plaintext)

def rsa_decrypt(ciphertext: bytes, private_key_bytes: bytes) -> bytes:
    key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)

def rsa_sign(message: bytes, private_key_bytes: bytes) -> bytes:
    key = RSA.import_key(private_key_bytes)
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)

def rsa_verify(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    key = RSA.import_key(public_key_bytes)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
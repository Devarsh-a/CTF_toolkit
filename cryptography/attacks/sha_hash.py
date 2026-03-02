# attacks/sha_hash.py
import hashlib

def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()
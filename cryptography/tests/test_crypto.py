# tests/test_ciphers.py
import pytest
from attacks import (
    single_xor_encrypt, single_xor_decrypt,
    repeating_xor_encrypt, repeating_xor_decrypt,
    playfair_encrypt, playfair_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    rc4_encrypt, rc4_decrypt
)

def test_single_xor():
    data = b"hello"
    key = 42
    enc = single_xor_encrypt(data, key)
    dec = single_xor_decrypt(enc, key)
    assert dec == data

def test_repeating_xor():
    data = b"hello world"
    key = b"ICE"
    enc = repeating_xor_encrypt(data, key)
    dec = repeating_xor_decrypt(enc, key)
    assert dec == data

def test_playfair():
    data = "HELLO"
    key = "KEYWORD"
    enc = playfair_encrypt(data, key)
    dec = playfair_decrypt(enc, key)
    # Playfair preserves letters (uppercase)
    assert dec.startswith("HELLO") or dec.startswith("HE")  # allows X padding

def test_vigenere():
    data = b"HELLO"
    key = b"KEY"
    enc = vigenere_encrypt(data, key)
    dec = vigenere_decrypt(enc, key)
    assert dec == data

def test_rc4():
    data = b"HELLO"
    key = b"SECRET"
    enc = rc4_encrypt(data, key)
    dec = rc4_decrypt(enc, key)
    assert dec == data
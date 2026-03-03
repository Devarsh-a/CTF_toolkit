import pytest

from engine import analyze
from attacks.single_xor import single_xor_encrypt
from attacks.caesar import increment_encrypt
from attacks.rot_n import rot_encrypt


def contains_plaintext(results, target: str):
    return any(
        target in r.decoded.decode(errors="ignore")
        for r in results
    )


# ---------------------------
# Single-byte XOR
# ---------------------------

def test_single_byte_xor_break():
    plaintext = b"attack at dawn"
    key = 42

    ciphertext = single_xor_encrypt(plaintext, key)

    results = analyze(ciphertext)

    assert contains_plaintext(results, "attack at dawn")


# ---------------------------
# Caesar Cipher
# ---------------------------

def test_caesar_break():
    plaintext = b"defend the east wall"
    shift = 5

    ciphertext = increment_encrypt(plaintext, shift)

    results = analyze(ciphertext)

    assert contains_plaintext(results, "defend the east wall")


# ---------------------------
# ROT Cipher
# ---------------------------

def test_rot_break():
    plaintext = b"rotate this message"
    shift = 13  # classic ROT13

    ciphertext = rot_encrypt(plaintext, shift)

    results = analyze(ciphertext)

    assert contains_plaintext(results, "rotate this message")
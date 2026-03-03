from attacks.single_xor import single_xor_encrypt
from engine import analyze


def test_single_byte_xor_break():
    plaintext = b"attack at dawn"
    key = 42

    ciphertext = single_xor_encrypt(plaintext, key)

    results = analyze(ciphertext)

    decoded_texts = [
        r.decoded.decode(errors="ignore")
        for r in results
    ]

    assert any("attack at dawn" in r.decoded.decode(errors="ignore") for r in results)
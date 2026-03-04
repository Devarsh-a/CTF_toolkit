import pytest
import base64
import binascii
from attacks import (
    single_xor_encrypt, single_xor_decrypt,
    repeating_xor_encrypt, repeating_xor_decrypt,
    playfair_encrypt, playfair_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    rc4_encrypt, rc4_decrypt,recursive_decode
)


# Import your decoder and EncodingResult
# from decoder_module import recursive_decode_multi, EncodingResult, try_rotx_wrapper, try_base16_file, TEXT_ATTEMPTS, COMPRESSION_ATTEMPTS

# ==========================================================
# Helper functions to create layered test data
# ==========================================================
def encode_rot(text: str, shift: int) -> str:
    """Apply ROT-X shift to ASCII printable characters"""
    def rot_char(c):
        ascii_val = ord(c)
        if 33 <= ascii_val <= 126:
            return chr(33 + ((ascii_val - 33 + shift) % 94))
        return c
    return "".join(rot_char(c) for c in text)

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode()).decode()

# ==========================================================
# Test Cases
# ==========================================================
@pytest.mark.parametrize(
    "plain_text,rot_shift",
    [
        ("Hello World!", 13),
        ("Secret123!", 47),
        ("Testing123 ROT-X", 23),
    ]
)
def test_three_layer_cipher(plain_text, rot_shift):
    """
    Test decoding of ROT-X -> Base64 -> Hex
    """
    # Encode layers
    step1 = encode_rot(plain_text, rot_shift)   # ROT-X
    step2 = encode_base64(step1)                # Base64
    step3 = encode_hex(step2)                   # Hex (final)

    # Decode
    results = recursive_decode(step3, max_depth=10, beam_width=20)

    # Check that at least one result matches original plaintext
    matches = [
        res for res in results
        if plain_text in res.decoded.decode("utf-8", errors="ignore")
    ]

    assert matches, f"Failed to decode layered cipher: {plain_text}"

    # Optional: print the first matching chain
    first = matches[0]
    print(f"\nDecoded chain: {' -> '.join(first.chain())}")
    print(f"Decoded text: {first.decoded.decode('utf-8')}")
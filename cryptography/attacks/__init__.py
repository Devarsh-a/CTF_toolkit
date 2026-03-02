# attacks/__init__.py

# --- Repeating / single-byte XOR ---
from .single_xor import single_xor_encrypt, single_xor_decrypt
from .repeating_xor import repeating_xor_encrypt, repeating_xor_decrypt, break_repeating_xor

# --- Classic Ciphers ---
from .caesar import increment_encrypt, increment_decrypt
from .vigenere import vigenere_encrypt, vigenere_decrypt
from .transposition import transposition_encrypt, transposition_decrypt
from .substitution import substitution_encrypt, substitution_decrypt
from .playfair import playfair_encrypt, playfair_decrypt

# --- Stream ciphers ---
from .rc4 import rc4_encrypt, rc4_decrypt

# --- Modern ciphers ---
from .aes_cipher import aes_encrypt, aes_decrypt
from .rsa_cipher import rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify
from .sha_hash import sha1, sha256, sha512
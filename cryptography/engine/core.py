# engine.py

from attacks import (
    single_xor, repeating_xor, caesar, rot_n, playfair, vigenere,
    transposition, substitution, rc4, aes_cipher
)

from attacks.encoding import recursive_decode
from .ml_scorer import PlaintextScorer



# Manual 


CIPHERS = {
    "single_xor": {"encrypt": single_xor.single_xor_encrypt, "decrypt": single_xor.single_xor_decrypt},
    "repeating_xor": {"encrypt": repeating_xor.repeating_xor_encrypt, "decrypt": repeating_xor.repeating_xor_decrypt},
    "caesar": {"encrypt": caesar.increment_encrypt, "decrypt": caesar.increment_decrypt},
    "rot": {"encrypt": rot_n.rot_encrypt, "decrypt": rot_n.rot_decrypt},
    "playfair": {"encrypt": playfair.playfair_encrypt, "decrypt": playfair.playfair_decrypt},
    "vigenere": {"encrypt": vigenere.vigenere_encrypt, "decrypt": vigenere.vigenere_decrypt},
    "transposition": {"encrypt": transposition.transposition_encrypt, "decrypt": transposition.transposition_decrypt},
    "substitution": {"encrypt": substitution.substitution_encrypt, "decrypt": substitution.substitution_decrypt},
    "rc4": {"encrypt": rc4.rc4_encrypt, "decrypt": rc4.rc4_decrypt},
    "aes_ecb": {"encrypt": aes_cipher.aes_encrypt, "decrypt": aes_cipher.aes_decrypt},
    "aes_cbc": {"encrypt": aes_cipher.aes_encrypt, "decrypt": aes_cipher.aes_decrypt},
}


def encrypt(plaintext: bytes, cipher_name: str, key: bytes = b"", **kwargs) -> bytes:
    if cipher_name not in CIPHERS:
        raise ValueError(f"Cipher '{cipher_name}' not supported")
    return CIPHERS[cipher_name]["encrypt"](plaintext, key, **kwargs)


def decrypt(ciphertext: bytes, cipher_name: str, key: bytes = b"", **kwargs) -> bytes:
    if cipher_name not in CIPHERS:
        raise ValueError(f"Cipher '{cipher_name}' not supported")
    return CIPHERS[cipher_name]["decrypt"](ciphertext, key, **kwargs)



# Intelligent Analysis Engine


def analyze(data, max_depth=3):
    """
    Full ML-guided cryptanalysis pipeline.
    Returns ranked decoding candidates.
    """

    scorer = PlaintextScorer()
    all_candidates = []

    # 1️ Recursive encoding/compression decoding
    
    recursive_results = recursive_decode(
        data,
        max_depth=max_depth,
        scorer=scorer.score
    )

    all_candidates.extend(recursive_results)

  
    # 2️ Single-byte XOR auto-break
    
    try:
        if isinstance(data, str):
            raw = data.encode(errors="ignore")
        else:
            raw = data

        xor_result = single_xor.break_single_xor(raw)

        if xor_result:
            all_candidates.append(
                _wrap_result(
                    xor_result["plaintext"],
                    "break_single_xor"
                )
            )
    except:
        pass

  
    # 3️ Repeating XOR auto-break
    
    try:
        repeating_result = repeating_xor.break_repeating_xor(raw)

        if repeating_result:
            all_candidates.append(
                _wrap_result(
                    repeating_result["plaintext"],
                    "repeating_xor_break"
                )
            )
    except:
        pass
    
    # 4️ Caesar auto-break
    try:
        caesar_result = caesar.break_caesar(raw)

        if caesar_result:
            all_candidates.append(
                _wrap_result(
                    caesar_result["plaintext"],
                    "caesar_break"
                )
            )
    except:
        pass
        
    # 5️ ROT auto-break
    try:
        rot_result = rot_n.break_rot(raw)

        if rot_result:
            all_candidates.append(
                _wrap_result(
                    rot_result["plaintext"],
                    "rot_break"
                )
            )
    except:
        pass

    # # 6 Vigenere auto-break
    # try:
    #     raw_bytes = data.encode(errors="ignore") if isinstance(data, str) else data
    #     vig_result = vigenere.break_vigenere(raw_bytes)
    #     if vig_result:
    #         all_candidates.append(
    #             _wrap_result(
    #                 vig_result["plaintext"],
    #                 "vigenere_break"
    #             )
    #         )
    # except:
    #     pass

    # 7 Rank Everything Using ML
    
    ranked = sorted(
        all_candidates,
        key=lambda r: scorer.score(_safe_decode(r.decoded)),
        reverse=True
    )

    return ranked



# Helpers


class _SimpleResult:
    def __init__(self, decoded: bytes, label: str):
        self.decoded = decoded
        self._label = label

    def chain(self):
        return [self._label]


def _wrap_result(decoded_bytes, label):
    return _SimpleResult(decoded_bytes, label)


def _safe_decode(b):
    try:
        return b.decode(errors="ignore")
    except:
        return ""
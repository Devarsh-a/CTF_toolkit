# attacks/transposition.py
def transposition_encrypt(plaintext: str, key: str) -> str:
    """Columnar transposition encryption"""
    num_cols = len(key)
    cols = [''] * num_cols
    for i, c in enumerate(plaintext):
        cols[i % num_cols] += c
    # Reorder columns alphabetically by key
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    ciphertext = ''.join(cols[i] for i in key_order)
    return ciphertext

def transposition_decrypt(ciphertext: str, key: str) -> str:
    """Columnar transposition decryption"""
    num_cols = len(key)
    n = len(ciphertext)
    col_lengths = [n // num_cols + (1 if i < n % num_cols else 0) for i in range(num_cols)]
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    
    # Split ciphertext into columns
    cols = {}
    idx = 0
    for k, l in zip(key_order, col_lengths):
        cols[k] = ciphertext[idx:idx+l]
        idx += l
    
    # Reconstruct plaintext row by row
    plaintext = ''
    for i in range(max(col_lengths)):
        for j in range(num_cols):
            if i < len(cols[j]):
                plaintext += cols[j][i]
    return plaintext
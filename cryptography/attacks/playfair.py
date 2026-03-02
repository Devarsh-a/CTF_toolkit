# attacks/playfair.py
import string

def generate_square(key: str) -> list:
    """Generate 5x5 Playfair square from key"""
    key = ''.join([c.upper() for c in key if c.isalpha()]).replace('J', 'I')
    seen = set()
    square = []
    
    # Add key letters first
    for c in key:
        if c not in seen:
            square.append(c)
            seen.add(c)
    
    # Add remaining letters
    for c in string.ascii_uppercase:
        if c == 'J':
            continue
        if c not in seen:
            square.append(c)
            seen.add(c)
    
    # 5x5 matrix
    return [square[i*5:(i+1)*5] for i in range(5)]

def find_position(square: list, char: str) -> tuple:
    """Find row,col of char in square"""
    for r, row in enumerate(square):
        for c, ch in enumerate(row):
            if ch == char:
                return r, c
    raise ValueError(f"Character {char} not in Playfair square")

def prepare_text(text: str) -> str:
    """Prepare text for encryption: uppercase, remove non-letters, replace J->I"""
    text = ''.join([c.upper() for c in text if c.isalpha()]).replace('J', 'I')
    prepared = ''
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            prepared += a + 'X'
            i += 1
        else:
            prepared += a + b
            i += 2
    if len(prepared) % 2 != 0:
        prepared += 'X'
    return prepared

def playfair_encrypt(plaintext: str, key: str) -> str:
    square = generate_square(key)
    text = prepare_text(plaintext)
    ciphertext = ''

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        ra, ca = find_position(square, a)
        rb, cb = find_position(square, b)

        if ra == rb:
            ciphertext += square[ra][(ca + 1) % 5] + square[rb][(cb + 1) % 5]
        elif ca == cb:
            ciphertext += square[(ra + 1) % 5][ca] + square[(rb + 1) % 5][cb]
        else:
            ciphertext += square[ra][cb] + square[rb][ca]

    return ciphertext

def playfair_decrypt(ciphertext: str, key: str) -> str:
    square = generate_square(key)
    plaintext = ''

    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        ra, ca = find_position(square, a)
        rb, cb = find_position(square, b)

        if ra == rb:
            plaintext += square[ra][(ca - 1) % 5] + square[rb][(cb - 1) % 5]
        elif ca == cb:
            plaintext += square[(ra - 1) % 5][ca] + square[(rb - 1) % 5][cb]
        else:
            plaintext += square[ra][cb] + square[rb][ca]

    return plaintext
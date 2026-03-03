# CTF Toolkit

This is a general-purpose CTF toolkit designed to **generalize scripts** commonly used to solve challenges in:

- **Forensics**
- **Cryptography**
- **Reverse Engineering**
- **Web Exploitation**

It includes encryption/decryption tools, automated cipher breaking, encoding/decoding utilities, and ML-guided plaintext scoring for analysis.

---

## CTF Cryptography Toolkit

A Python toolkit for encrypting, decrypting, and analyzing classical and modern ciphers. Includes ML-guided cryptanalysis for automated breaking of some ciphers.

---

## Features

### Supported Ciphers

- **Classical Ciphers**
  - Single-byte XOR
  - Repeating XOR
  - Caesar cipher
  - ROT-N
  - Playfair
  - Vigenère
  - Transposition
  - Substitution

- **Modern Ciphers**
  - RC4
  - AES (ECB and CBC modes)

- **Encoding & Compression**
  - Base64
  - gzip
  - Recursive decode support

- **Analysis**
  - ML-based plaintext scoring
  - Printable ratio, entropy, English frequency, structural patterns
  - Single-byte XOR and repeating XOR breaking
  - Partial support for Vigenère breaking

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Devarsh-a/CTF-toolkit.git
cd CTF-toolkit
```

## Make a Virtual environment

Create a virtual environment (optional but recommended):

```bash
python -m venv .venv
source .venv/bin/activate   # Linux / macOS
.venv\Scripts\activate      # Windows
```

## Install dependencies:

install dependencies
```bash
pip install -r requirements.txt
```

## Command-Line Usage
usage 

The toolkit also provides a simple command-line interface (CLI) to interact with ciphers and the analysis engine.

### Encrypt a Message

```bash
python -m engine encrypt --cipher vigenere --key "KEY" --input "Hello World"
```
    Example output:

    Ciphertext: b'Rijvs Uyvjn'

### Decrypt a Message

```bash
python -m engine decrypt --cipher vigenere --key "KEY" --input "Rijvs Uyvjn"
```
    Example output:

    Plaintext: b'Hello World'

### Analyze / Break a Cipher

```bash
python -m engine analyze --input "Rijvs Uyvjn"
```
    Example output:

    Candidate 1: Hello World (single_xor_break)
    Candidate 2: Rijvs Uyvjn (original)
    Candidate 3: ...

### CLI Options

--cipher : Cipher name (vigenere, caesar, rot, single_xor, repeating_xor, aes_ecb, aes_cbc, rc4, etc.)

--key : Key used for encryption/decryption (optional for analysis)

--input : Message to encrypt, decrypt, or analyze

--max-depth : Maximum recursion depth for analysis (default: 3)

## Notes:

Analysis mode (analyze) will attempt automated breaking using ML scoring and classical techniques.

For modern ciphers (AES, RC4), analysis cannot brute-force the key.

ML-guided scoring currently works best for English plaintext.

Some cipher-breaking functions (like Vigenère) assume ASCII plaintext.

Modern ciphers (AES, RC4) are not brute-forceable with the current engine.

Designed as a general CTF toolkit for cryptography, forensics, reverse engineering, and web exploitation challenges.



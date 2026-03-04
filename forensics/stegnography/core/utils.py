import math

def calculate_entropy(data):
    if not data:
        return 0
    probabilities = [data.count(bytes([i])) / len(data) for i in range(256)]
    return -sum([p * math.log2(p) for p in probabilities if p > 0])


def scan_magic_bytes(data):
    signatures = {
        b"\xFF\xD8\xFF": "JPEG",
        b"\x89PNG": "PNG",
        b"%PDF": "PDF",
        b"PK\x03\x04": "ZIP",
        b"GIF89a": "GIF"
    }
    findings = []
    for sig, name in signatures.items():
        if sig in data:
            findings.append(f"Embedded file signature detected: {name}")
    return findings
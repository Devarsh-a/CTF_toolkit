import base64
import gzip
from engine import analyze


def test_full_pipeline():
    original = b"flag{machine_learning_crypto}"
    compressed = gzip.compress(original)
    encoded = base64.b64encode(compressed)

    results = analyze(encoded)

    best = results[0].decoded.decode(errors="ignore")

    assert "flag{machine_learning_crypto}" in best
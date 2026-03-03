import gzip
import base64
from attacks.encoding import recursive_decode
from engine import PlaintextScorer


def test_base64_gzip():
    compressed = gzip.compress(b"secret message")
    encoded = base64.b64encode(compressed)

    results = recursive_decode(encoded, max_depth=5)

    scorer = PlaintextScorer()
    ranked = sorted(
        results,
        key=lambda r: scorer.score(r.decoded.decode(errors="ignore")),
        reverse=True
    )

    best = ranked[0].decoded.decode(errors="ignore")
    assert "secret message" in best
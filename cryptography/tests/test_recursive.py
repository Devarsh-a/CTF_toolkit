import base64
from attacks.encoding import recursive_decode
from engine import PlaintextScorer


def get_best_plaintext(results):
    scorer = PlaintextScorer()
    ranked = sorted(
        results,
        key=lambda r: scorer.score(r.decoded.decode(errors="ignore")),
        reverse=True
    )
    return ranked[0].decoded.decode(errors="ignore")


def test_single_base64():
    data = base64.b64encode(b"hello world")
    results = recursive_decode(data, max_depth=3)

    best = get_best_plaintext(results)
    assert "hello world" in best


def test_double_base64():
    data = base64.b64encode(base64.b64encode(b"hello world"))
    results = recursive_decode(data, max_depth=5)

    best = get_best_plaintext(results)
    assert "hello world" in best
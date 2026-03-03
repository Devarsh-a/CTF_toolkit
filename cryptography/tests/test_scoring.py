# tests/test_scoring.py
import pytest
import string
import random

from entropy import shannon_entropy, is_mostly_printable, alphabetic_ratio, space_ratio
from engine.ml_scorer import PlaintextScorer

# -------------------------
# Entropy / Heuristics Tests
# -------------------------
def test_shannon_entropy():
    low_entropy = b"AAAAAA"
    high_entropy = bytes(range(256))
    assert shannon_entropy(low_entropy) < shannon_entropy(high_entropy)


def test_alphabetic_ratio():
    text = "Hello World 123!"
    ratio = alphabetic_ratio(text)
    assert 0 < ratio < 1
    assert ratio > 0.5

def test_space_ratio():
    text = "Hello World from GPT"
    ratio = space_ratio(text)
    assert 0 < ratio < 1
    assert ratio == 3 / len(text)

# -------------------------
# PlaintextScorer Tests
# -------------------------
def test_scorer_prefers_plaintext():
    scorer = PlaintextScorer()
    plain = b"This is a test message"
    random_bytes = bytes(random.getrandbits(8) for _ in range(len(plain)))
    assert scorer.score(plain) > scorer.score(random_bytes)

def test_scorer_recognizes_common_words():
    scorer = PlaintextScorer()
    msg_with_words = b"the flag is here"
    msg_without_words = b"qwertyuiopasdfgh"
    assert scorer.score(msg_with_words) > scorer.score(msg_without_words)

def test_scorer_printable_bonus():
    scorer = PlaintextScorer()
    printable = b"Hello World!"
    nonprintable = b"\x00\x01\x02\x03"
    assert scorer.score(printable) > scorer.score(nonprintable)
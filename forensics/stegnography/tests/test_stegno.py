import os
import numpy as np
import wave
import pytest
from PIL import Image

from analyzers.image import ImageAnalyzer
from analyzers.audio import AudioAnalyzer
from analyzers.file import FileAnalyzer
from core.utils import calculate_entropy, scan_magic_bytes
from core.report import generate_report


# 
# 1️ ENTROPY TESTS
# 
def test_entropy_low():
    data = b"\x00" * 1000
    entropy = calculate_entropy(data)
    assert entropy < 1


def test_entropy_high():
    data = os.urandom(1000)
    entropy = calculate_entropy(data)
    assert entropy > 7


# 
# 2️ MAGIC BYTE TEST
# 
def test_magic_byte_detection():
    data = b"\x89PNG random data"
    findings = scan_magic_bytes(data)
    assert any("PNG" in f for f in findings)


# 
# 3️ IMAGE LSB TEST
# 
def test_image_lsb_extraction(tmp_path):
    # Create a tiny 8x8 image
    img_array = np.zeros((8, 8, 3), dtype=np.uint8)

    message = "HI"
    bits = ''.join(format(ord(c), '08b') for c in message) + "00000000"

    flat = img_array.flatten()
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)

    img_array = flat.reshape((8, 8, 3))
    img_path = tmp_path / "test.png"
    Image.fromarray(img_array).save(img_path)

    analyzer = ImageAnalyzer(str(img_path))
    analyzer.analyze()

    assert any("LSB hidden message" in f for f in analyzer.findings)


# 
# 4️ AUDIO LSB TEST
# 
def test_audio_lsb_extraction(tmp_path):
    audio_path = tmp_path / "test.wav"

    # Create simple WAV with hidden text
    message = "OK"
    bits = ''.join(format(ord(c), '08b') for c in message) + "00000000"
    frames = bytearray(1000)

    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & ~1) | int(bit)

    with wave.open(str(audio_path), 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(1)
        wf.setframerate(44100)
        wf.writeframes(frames)

    analyzer = AudioAnalyzer(str(audio_path))
    analyzer.analyze()

    assert any("LSB hidden message" in f for f in analyzer.findings)


# 
# 5️ FILE ANALYZER TEST
# 
def test_file_analyzer_entropy(tmp_path):
    file_path = tmp_path / "random.bin"
    file_path.write_bytes(os.urandom(2000))

    analyzer = FileAnalyzer(str(file_path))
    analyzer.analyze()

    assert any("High entropy" in f for f in analyzer.findings)


# 
# 6️ REPORT GENERATION TEST
# 
def test_generate_report(tmp_path):
    results = {
        "file1.png": ["High entropy"],
        "file2.wav": []
    }

    report_path = tmp_path / "report.txt"
    generate_report(results, report_path)

    assert report_path.exists()

    content = report_path.read_text()
    assert "file1.png" in content
    assert "High entropy" in content
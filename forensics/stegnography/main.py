import os
from analyzers.image import ImageAnalyzer
from analyzers.audio import AudioAnalyzer
from analyzers.file import FileAnalyzer
from core.report import generate_report

INPUT_DIR = "stego_files"
OUTPUT_DIR = "stego_output"
REPORT_FILE = os.path.join(OUTPUT_DIR, "forensic_report.txt")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_analyzer(filepath):
    if filepath.lower().endswith((".png", ".bmp", ".jpg", ".jpeg")):
        return ImageAnalyzer(filepath)
    elif filepath.lower().endswith(".wav"):
        return AudioAnalyzer(filepath)
    else:
        return FileAnalyzer(filepath)


def main():
    results = {}

    for file in os.listdir(INPUT_DIR):
        path = os.path.join(INPUT_DIR, file)
        analyzer = get_analyzer(path)
        analyzer.analyze()
        results[file] = analyzer.findings

    generate_report(results, REPORT_FILE)
    print("Steganography forensic analysis completed.")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
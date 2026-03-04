from core.base import Analyzer
from core.utils import calculate_entropy, scan_magic_bytes


class FileAnalyzer(Analyzer):

    def analyze(self):
        try:
            with open(self.filepath, "rb") as f:
                raw = f.read()

            entropy = calculate_entropy(raw)
            if entropy > 7.5:
                self.findings.append(f"High entropy ({entropy:.2f})")

            self.findings.extend(scan_magic_bytes(raw))

        except Exception as e:
            self.findings.append(f"Error analyzing file: {e}")
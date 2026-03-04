import wave
import contextlib
from core.base import Analyzer
from core.utils import calculate_entropy


class AudioAnalyzer(Analyzer):

    def analyze(self):
        try:
            with contextlib.closing(wave.open(self.filepath, 'rb')) as wf:
                frames = wf.readframes(wf.getnframes())

                bits = [frame & 1 for frame in frames]
                bytes_list = [bits[i:i+8] for i in range(0, len(bits), 8)]

                message = ""
                for byte_bits in bytes_list:
                    if len(byte_bits) < 8:
                        break
                    value = 0
                    for bit in byte_bits:
                        value = (value << 1) | bit
                    if value == 0:
                        break
                    if 32 <= value <= 126:
                        message += chr(value)

                if message:
                    self.findings.append("Possible LSB hidden message in audio.")

            with open(self.filepath, "rb") as f:
                raw = f.read()
                entropy = calculate_entropy(raw)
                if entropy > 7.5:
                    self.findings.append(f"High entropy ({entropy:.2f})")

        except Exception as e:
            self.findings.append(f"Error analyzing audio: {e}")
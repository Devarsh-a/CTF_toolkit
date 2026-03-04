import numpy as np
from PIL import Image, ExifTags
from core.base import Analyzer
from core.utils import calculate_entropy, scan_magic_bytes


class ImageAnalyzer(Analyzer):

    def extract_lsb(self, img_array):
        bits = [pixel & 1 for pixel in img_array.flatten()]
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

        return message

    def analyze(self):
        try:
            img = Image.open(self.filepath)
            img_array = np.array(img)

            # LSB extraction
            message = self.extract_lsb(img_array)
            if message:
                self.findings.append("Possible LSB hidden message detected.")

            # EXIF metadata
            if hasattr(img, "_getexif") and img._getexif():
                self.findings.append("EXIF metadata present.")

            # Entropy
            with open(self.filepath, "rb") as f:
                raw = f.read()
                entropy = calculate_entropy(raw)
                if entropy > 7.5:
                    self.findings.append(f"High entropy ({entropy:.2f})")

                self.findings.extend(scan_magic_bytes(raw))

        except Exception as e:
            self.findings.append(f"Error analyzing image: {e}")
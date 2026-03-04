import base64
import binascii
import urllib.parse
import html
import gzip
import zlib
import bz2
import lzma



# ==========================================================
# Result Object
# ==========================================================

class EncodingResult:
    def __init__(self, decoded: bytes, encoding_type: str, parent=None, depth=0):
        self.decoded = decoded              # Always bytes
        self.encoding_type = encoding_type
        self.parent = parent
        self.depth = depth

    def chain(self):
        chain = []
        node = self
        while node:
            chain.append(node.encoding_type)
            node = node.parent
        return list(reversed(chain))


# ==========================================================
# Text-Based Encoding Attempts
# ==========================================================

def try_base16(data: str):
    try:
        decoded = binascii.unhexlify(data.strip())
        return decoded, "base16"
    except:
        return None

def try_base16_file(data: str):
    try:
        # Remove all whitespace (spaces, newlines, tabs)
        cleaned = "".join(data.split())
        # If odd length, prepend a zero
        if len(cleaned) % 2:
            cleaned = "0" + cleaned
        decoded = binascii.unhexlify(cleaned)
        return decoded, "base16_file"
    except:
        return None

def try_base32(data: str):
    try:
        decoded = base64.b32decode(data.strip(), casefold=True)
        return decoded, "base32"
    except:
        return None


def try_base64(data: str):
    try:
        decoded = base64.b64decode(data.strip())
        return decoded, "base64"
    except:
        return None


def try_base85(data: str):
    try:
        decoded = base64.b85decode(data.strip())
        return decoded, "base85"
    except:
        return None


def try_ascii85(data: str):
    try:
        decoded = base64.a85decode(data.strip())
        return decoded, "ascii85"
    except:
        return None


def try_url_decode(data: str):
    try:
        decoded = urllib.parse.unquote(data)
        return decoded.encode(), "url"
    except:
        return None


def try_html_decode(data: str):
    try:
        decoded = html.unescape(data)
        return decoded.encode(), "html"
    except:
        return None


def try_binary(data: str):
    try:
        stripped = data.strip()
        if stripped and set(stripped) <= {"0", "1", " "}:
            parts = stripped.split()
            decoded = bytes(int(b, 2) for b in parts)
            return decoded, "binary"
    except:
        pass
    return None


def try_octal(data: str):
    try:
        stripped = data.strip()
        if stripped and set(stripped) <= set("01234567 "):
            parts = stripped.split()
            decoded = bytes(int(o, 8) for o in parts)
            return decoded, "octal"
    except:
        pass
    return None
def try_rotx(data: str, shifts=None):
    """
    Attempt all ROT-X shifts on printable ASCII.
    Returns a list of tuples (decoded_bytes, encoding_type)
    """
    if shifts is None:
        # Try all shifts from 1 to 94
        shifts = range(1, 95)

    results = []
    for shift in shifts:
        try:
            decoded = []
            for c in data:
                ascii_val = ord(c)
                if 33 <= ascii_val <= 126:  # printable ASCII
                    decoded_val = 33 + ((ascii_val - 33 + shift) % 94)
                    decoded.append(chr(decoded_val))
                else:
                    decoded.append(c)
            decoded_bytes = "".join(decoded).encode()
            results.append((decoded_bytes, f"rot{shift}"))
        except:
            continue
    return results if results else None
def try_rotx_wrapper(data: str):
    results = try_rotx(data, shifts=range(1, 95))
    # For beam search, just return the first result (can be pruned later)
    if results:
        # Only return the first result here, recursive decoder will explore all depths
        return results[0]
    return None


TEXT_ATTEMPTS = [
    try_rotx_wrapper,
    try_base16_file,
    try_base16,
    try_base32,
    try_base64,
    try_base85,
    try_ascii85,
    try_url_decode,
    try_html_decode,
    try_binary,
    try_octal,
]


# ==========================================================
# Compression Attempts (Byte-Level Only)
# ==========================================================

def try_gzip_bytes(data_bytes: bytes):
    try:
        if data_bytes.startswith(b"\x1f\x8b"):
            return gzip.decompress(data_bytes), "gzip"
    except:
        pass
    return None


def try_zlib_bytes(data_bytes: bytes):
    try:
        if data_bytes.startswith((b"\x78\x01", b"\x78\x9c", b"\x78\xda")):
            return zlib.decompress(data_bytes), "zlib"
    except:
        pass
    return None


def try_bz2_bytes(data_bytes: bytes):
    try:
        if data_bytes.startswith(b"BZh"):
            return bz2.decompress(data_bytes), "bz2"
    except:
        pass
    return None


def try_lzma_bytes(data_bytes: bytes):
    try:
        if data_bytes.startswith(b"\xfd7zXZ"):
            return lzma.decompress(data_bytes), "lzma"
    except:
        pass
    return None


COMPRESSION_ATTEMPTS = [
    try_gzip_bytes,
    try_zlib_bytes,
    try_bz2_bytes,
    try_lzma_bytes,
]


# ==========================================================
# Recursive Decode Engine
# ==========================================================

def recursive_decode(
    data,
    max_depth=5,  # allow deeper recursion for nested encodings
    stop_on_printable=False,
    scorer=None,
    beam_width=25
):
    """
    Robust recursive decoder with beam search.
    Supports messy hex files, base encodings, and compression.
    """
    if isinstance(data, str):
        initial_bytes = data.encode(errors="ignore")
    elif isinstance(data, bytes):
        initial_bytes = data
    else:
        raise TypeError("Input must be str or bytes")

    visited = set()
    results = []

    # Each item: (bytes, parent_result, depth)
    current_level = [(initial_bytes, None, 1)]

    for depth in range(1, max_depth + 1):
        next_level = []

        for current_bytes, parent_result, depth in current_level:
            if current_bytes in visited:
                continue
            visited.add(current_bytes)

            # ---------------------
            # Compression attempts
            # ---------------------
            for comp in COMPRESSION_ATTEMPTS:
                outcome = comp(current_bytes)
                if outcome:
                    decoded_bytes, enc_type = outcome
                    result = EncodingResult(
                        decoded=decoded_bytes,
                        encoding_type=enc_type,
                        parent=parent_result,
                        depth=depth
                    )
                    results.append(result)
                    next_level.append((decoded_bytes, result, depth + 1))

            # ---------------------
            # Text encoding attempts
            # ---------------------
            try:
                current_text = current_bytes.decode(errors="ignore")
            except:
                continue

            for attempt in TEXT_ATTEMPTS:
                outcome = attempt(current_text)
                if outcome:
                    decoded_bytes, enc_type = outcome
                    result = EncodingResult(
                        decoded=decoded_bytes,
                        encoding_type=enc_type,
                        parent=parent_result,
                        depth=depth
                    )
                    results.append(result)
                    next_level.append((decoded_bytes, result, depth + 1))

        #  Beam pruning
        if scorer:
            next_level = sorted(
                next_level,
                key=lambda x: scorer(x[0].decode(errors="ignore")),
                reverse=True
            )[:beam_width]
        else:
            next_level = next_level[:beam_width]

        current_level = next_level
        if not current_level:
            break

    return results
# ==========================================================
# Utility
# ==========================================================

def is_mostly_printable(text: str, threshold=0.85):
    if not text:
        return False
    printable = sum(c.isprintable() for c in text)
    return printable / len(text) > threshold



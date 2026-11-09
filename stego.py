"""LSB steganography for brand logos and marketing assets (OpenCV + NumPy).

embed_serial() hides a unique serial number (for example RGD-2026-9F3A1C7E) in the least-significant bits of an
image's blue/green/red pixels and returns a lossless PNG. extract_serial() reads it back. The bit positions are
chosen from the secret STEGO_KEY, so only someone with the key can find (or forge) the mark.

Payload layout: magic "RGD\\x01" | length (1 byte) | serial (ASCII) | CRC-32 of the serial (4 bytes).

Honest limit: an LSB mark survives byte-for-byte copies and lossless re-saves (PNG). It is destroyed by JPEG/WebP
re-compression, resizing, cropping or a screenshot. Use it together with exact-hash matching.
"""
import hashlib
import logging
import math
import os
import struct
import zlib

import cv2
import numpy as np

log = logging.getLogger("DRP-Stego")
MAGIC = b"RGD\x01"
MAX_PIXELS = int(os.getenv("STEGO_MAX_PIXELS", "40000000"))
MAX_SERIAL_LEN = 64
_warned = False


class StegoError(ValueError):
    """Raised when a mark cannot be embedded (bad serial, unreadable or too small image)."""


def _key():
    global _warned
    key = os.getenv("STEGO_KEY")
    if not key:
        if not _warned:
            log.warning("STEGO_KEY is not set: using a built-in development key. Set STEGO_KEY in production.")
            _warned = True
        key = "rorgid-development-stego-key"
    return key.encode()


def peek_dimensions(data):
    """(width, height) read from the PNG or JPEG header without decoding, or None."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR" and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return w, h
    if data[:3] == b"\xff\xd8\xff":
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            m = data[i + 1]
            if m == 0xFF:
                i += 1
            elif m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
                i += 2
            else:
                seg = struct.unpack(">H", data[i + 2:i + 4])[0]
                if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return w, h
                i += 2 + seg
    return None


def _decode(data):
    dims = peek_dimensions(data)
    if dims is None:
        raise StegoError("only PNG and JPEG images are supported")
    if dims[0] * dims[1] > MAX_PIXELS or dims[0] < 1 or dims[1] < 1:
        raise StegoError("image dimensions are too large")
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_UNCHANGED)
    if img is None:
        raise StegoError("not a readable image")
    if img.dtype == np.uint16:
        img = (img >> 8).astype(np.uint8)
    elif img.dtype != np.uint8:
        raise StegoError("unsupported pixel format")
    if img.ndim == 2:
        img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    return img


def _positions(total, nbits):
    """Keyed walk over the pixel-channel bytes. Position i never depends on nbits, so a reader can fetch the
    header first and then the rest."""
    h = hashlib.sha256(_key()).digest()
    start = int.from_bytes(h[:8], "big") % total
    step = int.from_bytes(h[8:16], "big") % max(total - 2, 1) + 1
    while math.gcd(step, total) != 1:                     # coprime step: no position is used twice
        step = step % (total - 1) + 1 if total > 2 else 1
    return (start + np.arange(nbits, dtype=np.int64) * step) % total


def _payload(serial):
    raw = serial.encode("ascii")
    return MAGIC + bytes([len(raw)]) + raw + struct.pack(">I", zlib.crc32(raw))


def capacity_ok(width, height, serial):
    return (len(_payload(serial))) * 8 <= width * height * 3


def embed_serial(data, serial):
    """Returns PNG bytes of the image with `serial` hidden in it."""
    if not serial or len(serial) > MAX_SERIAL_LEN or not serial.isascii() or not serial.isprintable():
        raise StegoError("serial must be 1 to 64 printable ASCII characters")
    img = _decode(data)
    bgr = np.ascontiguousarray(img[:, :, :3])
    flat = bgr.reshape(-1)
    bits = np.unpackbits(np.frombuffer(_payload(serial), np.uint8))
    if len(bits) > flat.size:
        raise StegoError("image is too small to hold the serial number")
    idx = _positions(flat.size, len(bits))
    flat[idx] = (flat[idx] & 0xFE) | bits
    img[:, :, :3] = bgr
    ok, png = cv2.imencode(".png", img, [cv2.IMWRITE_PNG_COMPRESSION, 6])
    if not ok:
        raise StegoError("could not encode the PNG")
    return png.tobytes()


def extract_serial(data):
    """Returns the hidden serial, or None (never raises) when there is no valid mark."""
    try:
        img = _decode(data)
        flat = np.ascontiguousarray(img[:, :, :3]).reshape(-1)
        if flat.size < 72:
            return None
        head = np.packbits(flat[_positions(flat.size, 40)] & 1).tobytes()
        if head[:4] != MAGIC:
            return None
        n = head[4]
        if not 1 <= n <= MAX_SERIAL_LEN or (5 + n + 4) * 8 > flat.size:
            return None
        body = np.packbits(flat[_positions(flat.size, (5 + n + 4) * 8)] & 1).tobytes()
        raw, crc = body[5:5 + n], struct.unpack(">I", body[5 + n:9 + n])[0]
        if zlib.crc32(raw) != crc:
            return None
        return raw.decode("ascii")
    except Exception:
        return None

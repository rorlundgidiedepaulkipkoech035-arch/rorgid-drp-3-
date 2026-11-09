"""Tests for the OpenCV/NumPy LSB steganography (no database or network needed)."""
import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["STEGO_KEY"] = "test-key-one"

import cv2  # noqa: E402
import numpy as np  # noqa: E402
from src import stego  # noqa: E402

SERIAL = "RGD-2026-9F3A1C7E"


def make_png(w=200, h=160, alpha=False, seed=1):
    rng = np.random.default_rng(seed)
    img = rng.integers(0, 256, (h, w, 4 if alpha else 3), dtype=np.uint8)
    return cv2.imencode(".png", img)[1].tobytes()


def make_jpg(w=200, h=160, q=95):
    rng = np.random.default_rng(2)
    return cv2.imencode(".jpg", rng.integers(0, 256, (h, w, 3), dtype=np.uint8), [cv2.IMWRITE_JPEG_QUALITY, q])[1].tobytes()


def decode(b):
    return cv2.imdecode(np.frombuffer(b, np.uint8), cv2.IMREAD_UNCHANGED)


class StegoTests(unittest.TestCase):
    def setUp(self):
        os.environ["STEGO_KEY"] = "test-key-one"

    def test_roundtrip_png(self):
        out = stego.embed_serial(make_png(), SERIAL)
        self.assertEqual(stego.extract_serial(out), SERIAL)

    def test_change_is_invisible(self):
        src = make_png()
        out = stego.embed_serial(src, SERIAL)
        diff = np.abs(decode(src).astype(int) - decode(out).astype(int))
        self.assertLessEqual(diff.max(), 1)                                # at most one grey level per channel
        self.assertLess(np.count_nonzero(diff), 300)                       # only ~200 bytes touched of 96,000

    def test_alpha_png_keeps_transparency(self):
        src = make_png(alpha=True)
        out = stego.embed_serial(src, SERIAL)
        self.assertTrue(np.array_equal(decode(src)[:, :, 3], decode(out)[:, :, 3]))
        self.assertEqual(stego.extract_serial(out), SERIAL)

    def test_jpeg_input_gives_png_output(self):
        out = stego.embed_serial(make_jpg(), SERIAL)
        self.assertEqual(out[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(stego.extract_serial(out), SERIAL)

    def test_grayscale_png(self):
        g = cv2.imencode(".png", np.random.default_rng(3).integers(0, 256, (120, 120), dtype=np.uint8))[1].tobytes()
        self.assertEqual(stego.extract_serial(stego.embed_serial(g, SERIAL)), SERIAL)

    def test_wrong_key_and_clean_image(self):
        out = stego.embed_serial(make_png(), SERIAL)
        os.environ["STEGO_KEY"] = "a-different-key"
        self.assertIsNone(stego.extract_serial(out))
        os.environ["STEGO_KEY"] = "test-key-one"
        self.assertIsNone(stego.extract_serial(make_png()))                # never marked

    def test_different_serials_are_independent(self):
        a, b = stego.embed_serial(make_png(), "RGD-2026-AAAA1111"), stego.embed_serial(make_png(), "RGD-2026-BBBB2222")
        self.assertEqual((stego.extract_serial(a), stego.extract_serial(b)), ("RGD-2026-AAAA1111", "RGD-2026-BBBB2222"))

    def test_mark_does_not_survive_lossy_changes(self):
        out = stego.embed_serial(make_png(), SERIAL)
        img = decode(out)
        jpg = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])[1].tobytes()
        self.assertIsNone(stego.extract_serial(jpg))                       # re-compression destroys it
        small = cv2.imencode(".png", cv2.resize(img, (100, 80)))[1].tobytes()
        self.assertIsNone(stego.extract_serial(small))                     # resizing destroys it
        self.assertEqual(stego.extract_serial(cv2.imencode(".png", img)[1].tobytes()), SERIAL)   # lossless re-save is fine

    def test_rejects_bad_input(self):
        with self.assertRaises(stego.StegoError):
            stego.embed_serial(make_png(5, 5), SERIAL)                     # too small
        for bad in ("", "x" * 65, "RGD-é-1", "line\nbreak"):
            with self.assertRaises(stego.StegoError):
                stego.embed_serial(make_png(), bad)
        with self.assertRaises(stego.StegoError):
            stego.embed_serial(b"not an image", SERIAL)
        self.assertIsNone(stego.extract_serial(b"not an image"))
        self.assertIsNone(stego.extract_serial(b""))

    def test_decompression_bomb_header_is_refused_before_decoding(self):
        bomb = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 100000, 100000) + b"\x08\x02\x00\x00\x00" + b"\0" * 8
        self.assertEqual(stego.peek_dimensions(bomb), (100000, 100000))
        t = time.time()
        self.assertIsNone(stego.extract_serial(bomb))
        self.assertLess(time.time() - t, 1)
        with self.assertRaises(stego.StegoError):
            stego.embed_serial(bomb, SERIAL)

    def test_large_logo_is_fast(self):
        big = cv2.imencode(".png", np.full((2400, 3200, 3), 200, np.uint8))[1].tobytes()
        t = time.time()
        out = stego.embed_serial(big, SERIAL)
        self.assertEqual(stego.extract_serial(out), SERIAL)
        self.assertLess(time.time() - t, 10)

    def test_jpeg_dimension_peek(self):
        self.assertEqual(stego.peek_dimensions(make_jpg(123, 77)), (123, 77))
        self.assertEqual(stego.peek_dimensions(make_png(50, 40)), (50, 40))
        self.assertIsNone(stego.peek_dimensions(b"GIF89a....."))


if __name__ == "__main__":
    unittest.main(verbosity=2)

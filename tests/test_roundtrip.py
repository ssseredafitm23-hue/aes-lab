import os
import secrets
import tempfile
import unittest
from pathlib import Path

from key_manager import KeyManager
from crypto_aes import (
    encrypt_file, decrypt_file, read_header
)
from tamper_demo import mutate


class TestAES(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)

        cls.root = Path(tmp.name)
        cls.km = KeyManager(cls.root / "keystore.json")
        cls.password = secrets.token_urlsafe(24)
        cls.original = os.urandom(137)
        cls.source = cls.root / "source.bin"
        cls.source.write_bytes(cls.original)
        cls.fixtures = {}

        for mode in ("CBC-HMAC", "GCM"):
            cls.km.new_key(mode, cls.password)

            meta, enc, mac = cls.km.reserve_for_encryption(
                mode, cls.password
            )

            path = cls.root / f"{mode}.enc"

            tag = encrypt_file(
                cls.source, path, mode,
                enc, mac, meta["key_id"]
            )

            cls.fixtures[mode] = (
                path, meta, enc, mac, tag
            )

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)

    def test_roundtrip(self):
        for mode, fixture in self.fixtures.items():
            with self.subTest(mode=mode):
                path, meta, enc, mac, tag = fixture
                out = self.work / f"{mode}.dec"

                detected = decrypt_file(
                    path, out, enc, mac, meta["key_id"]
                )

                self.assertEqual(detected, mode)
                self.assertEqual(out.read_bytes(), self.original)

                self.assertEqual(
                    tag, 16 if mode == "GCM" else 32
                )

                self.assertEqual(
                    read_header(path)["mode"], mode
                )

    def test_ciphertext_tampering(self):
        self.check_tampering("ciphertext")

    def test_tag_tampering(self):
        self.check_tampering("tag")

    def test_header_tampering(self):
        self.check_tampering("header")

    def check_tampering(self, part):
        for mode, fixture in self.fixtures.items():
            with self.subTest(mode=mode, part=part):
                path, meta, enc, mac, _ = fixture

                bad = self.work / f"{mode}.enc"
                out = self.work / f"{mode}.dec"

                bad.write_bytes(
                    mutate(path.read_bytes(), part)
                )

                with self.assertRaisesRegex(
                    ValueError, "Authentication failed"
                ):
                    decrypt_file(
                        bad, out, enc, mac, meta["key_id"]
                    )

                self.assertFalse(out.exists())

    def test_truncated_container(self):
        for mode, fixture in self.fixtures.items():
            with self.subTest(mode=mode):
                path, meta, enc, mac, _ = fixture
                bad = self.work / f"{mode}.enc"
                out = self.work / f"{mode}.dec"

                bad.write_bytes(path.read_bytes()[:-1])

                with self.assertRaises(ValueError):
                    decrypt_file(
                        bad, out, enc, mac, meta["key_id"]
                    )

                self.assertFalse(out.exists())

    def test_invalid_header(self):
        bad = self.work / "invalid.enc"
        bad.write_bytes(b"INVALID-CONTAINER")

        with self.assertRaises(ValueError):
            read_header(bad)

    def test_wrong_password(self):
        for mode in self.fixtures:
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.km.derive_keypair(
                        mode, "Wrong-test-password"
                    )

    def test_key_reuse(self):
        for mode in self.fixtures:
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(
                    ValueError, "Key reuse prohibited"
                ):
                    self.km.reserve_for_encryption(
                        mode, self.password
                    )

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_file(
                self.source, self.work / "invalid.enc",
                "GCM", b"short", os.urandom(32), "0" * 64
            )

    def test_output_overwrite_protection(self):
        for mode, fixture in self.fixtures.items():
            with self.subTest(mode=mode):
                path, meta, enc, mac, _ = fixture
                out = self.work / f"{mode}.dec"
                out.write_bytes(b"KEEP EXISTING DATA")

                with self.assertRaises(FileExistsError):
                    decrypt_file(
                        path, out, enc, mac, meta["key_id"]
                    )

                self.assertEqual(
                    out.read_bytes(), b"KEEP EXISTING DATA"
                )

    def test_edge_sizes(self):
        for mode in ("CBC-HMAC", "GCM"):
            for size in (0, 16, 17):
                with self.subTest(mode=mode, size=size):
                    label = f"edge-{mode}-{size}"

                    self.km.new_key(label, self.password)

                    meta, enc, mac = (
                        self.km.reserve_for_encryption(
                            label, self.password
                        )
                    )

                    source = self.work / f"{label}.bin"
                    encrypted = self.work / f"{label}.enc"
                    restored = self.work / f"{label}.dec"

                    source.write_bytes(os.urandom(size))

                    encrypt_file(
                        source, encrypted, mode,
                        enc, mac, meta["key_id"]
                    )

                    decrypt_file(
                        encrypted, restored,
                        enc, mac, meta["key_id"]
                    )

                    self.assertEqual(
                        source.read_bytes(),
                        restored.read_bytes()
                    )

    def test_keystore_security(self):
        keys = self.km.list_keys()

        self.assertEqual(
            len({k["salt"] for k in keys}), len(keys)
        )

        self.assertEqual(
            len({k["key_id"] for k in keys}), len(keys)
        )

        self.assertEqual(
            self.km.path.stat().st_mode & 0o777,
            0o600
        )

        for meta in keys:
            self.assertNotIn("password", meta)
            self.assertNotIn("enc_key", meta)
            self.assertNotIn("mac_key", meta)


if __name__ == "__main__":
    unittest.main()

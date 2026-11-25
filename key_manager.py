import os
import json
import time
import hmac
import hashlib
import tempfile
import fcntl
from pathlib import Path
from contextlib import contextmanager

from config import (
    KEYSTORE_PATH, ITERATIONS,
    AES_KEY_BYTES, HMAC_KEY_BYTES
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class KeyManager:
    def __init__(self, path=KEYSTORE_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _lock(self):
        lock_path = str(self.path) + ".lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _load(self):
        if not self.path.exists():
            return {"keys": []}
        with self.path.open("r", encoding="utf-8") as f:
            db = json.load(f)
        if not isinstance(db.get("keys"), list):
            raise ValueError("Invalid keystore")
        return db

    def _save(self, db):
        fd, tmp = tempfile.mkstemp(dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(db, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    @staticmethod
    def _derive(password, salt, iterations):
        if len(salt) != 16:
            raise ValueError("Invalid salt length")
        if not 310_000 <= iterations <= 2_000_000:
            raise ValueError("Invalid iteration count")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_BYTES + HMAC_KEY_BYTES,
            salt=salt,
            iterations=iterations
        )
        material = kdf.derive(password.encode("utf-8"))
        enc_key = material[:AES_KEY_BYTES]
        mac_key = material[AES_KEY_BYTES:]

        if len(enc_key) != 32 or len(mac_key) != 32:
            raise ValueError("Invalid key length")

        return enc_key, mac_key

    @staticmethod
    def _key_id(enc_key):
        return hashlib.sha256(enc_key).hexdigest()

    def new_key(self, label, password, iterations=ITERATIONS):
        if not label.strip() or len(label) > 64:
            raise ValueError("Invalid key label")
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")

        with self._lock():
            db = self._load()

            if any(k["label"] == label for k in db["keys"]):
                raise ValueError("Key label already exists")

            salt = os.urandom(16)
            enc_key, mac_key = self._derive(
                password, salt, iterations
            )
            key_id = self._key_id(enc_key)

            if any(k["key_id"] == key_id for k in db["keys"]):
                raise ValueError("Duplicate key material")

            meta = {
                "label": label,
                "key_id": key_id,
                "salt": salt.hex(),
                "iterations": iterations,
                "kdf": "PBKDF2-HMAC-SHA256",
                "created_at": int(time.time()),
                "uses": 0
            }

            db["keys"].append(meta)
            self._save(db)
            return meta

    def list_keys(self):
        return self._load()["keys"]

    @staticmethod
    def _find(db, label):
        for meta in db["keys"]:
            if meta["label"] == label:
                return meta
        raise ValueError("Key label not found")

    def _derive_meta(self, meta, password):
        enc_key, mac_key = self._derive(
            password,
            bytes.fromhex(meta["salt"]),
            meta["iterations"]
        )

        if not hmac.compare_digest(
            self._key_id(enc_key), meta["key_id"]
        ):
            raise ValueError("Invalid password or key metadata")

        return meta, enc_key, mac_key

    def derive_keypair(self, label, password):
        meta = self._find(self._load(), label)
        return self._derive_meta(meta, password)

    def reserve_for_encryption(self, label, password):
        with self._lock():
            db = self._load()
            meta = self._find(db, label)

            if meta["uses"] != 0:
                raise ValueError("Key reuse prohibited")

            _, enc_key, mac_key = self._derive_meta(meta, password)
            meta["uses"] = 1
            self._save(db)

            return meta, enc_key, mac_key

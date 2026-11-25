import os
import json
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    MAGIC, VERSION, AES_KEY_BYTES,
    HMAC_KEY_BYTES, IV_BYTES_CBC, NONCE_BYTES_GCM
)

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_HEADER_BYTES = 4096

MODE_CONFIG = {
    "CBC-HMAC": {
        "alg": "AES-256-CBC",
        "padding": "PKCS7",
        "tag_bytes": 32
    },
    "GCM": {
        "alg": "AES-256-GCM",
        "padding": "NONE",
        "tag_bytes": 16
    }
}


def _pack_header(header):
    blob = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    if not 0 < len(blob) <= MAX_HEADER_BYTES:
        raise ValueError("Invalid header size")

    return MAGIC + struct.pack(">H", len(blob)) + blob


def _read_header(fp):
    prefix = fp.read(6)

    if len(prefix) != 6 or prefix[:4] != MAGIC:
        raise ValueError("Invalid container")

    size = struct.unpack(">H", prefix[4:])[0]

    if not 0 < size <= MAX_HEADER_BYTES:
        raise ValueError("Invalid header size")

    blob = fp.read(size)

    if len(blob) != size:
        raise ValueError("Truncated header")

    header = json.loads(blob.decode("utf-8"))

    if not isinstance(header, dict):
        raise ValueError("Invalid header")

    if header.get("v") != VERSION:
        raise ValueError("Unsupported container version")

    mode = header.get("mode")

    if mode not in MODE_CONFIG:
        raise ValueError("Unsupported AES mode")

    cfg = MODE_CONFIG[mode]

    if header.get("alg") != cfg["alg"]:
        raise ValueError("Invalid algorithm")

    if header.get("padding") != cfg["padding"]:
        raise ValueError("Invalid padding")

    key_id = header.get("key_id", "")

    if not isinstance(key_id, str) or len(key_id) != 64:
        raise ValueError("Invalid key identifier")

    bytes.fromhex(key_id)

    if mode == "GCM":
        nonce = bytes.fromhex(header["nonce"])
        if len(nonce) != NONCE_BYTES_GCM:
            raise ValueError("Invalid nonce length")
    else:
        iv = bytes.fromhex(header["iv"])
        if len(iv) != IV_BYTES_CBC:
            raise ValueError("Invalid IV length")

    return header, prefix + blob


def read_header(path):
    with open(path, "rb") as fp:
        header, _ = _read_header(fp)
    return header


def _validate_keys(enc_key, mac_key):
    if len(enc_key) != AES_KEY_BYTES:
        raise ValueError("AES key must be 256 bits")
    if len(mac_key) != HMAC_KEY_BYTES:
        raise ValueError("HMAC key must be 256 bits")


def _write_new(path, data):
    path = Path(path)

    if path.exists():
        raise FileExistsError("Output file already exists")

    fd, tmp = tempfile.mkstemp(dir=path.parent)

    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
        os.link(tmp, path)
    finally:
        os.unlink(tmp)


def encrypt_file(in_path, out_path, mode,
                 enc_key, mac_key, key_id):

    _validate_keys(enc_key, mac_key)

    if mode not in MODE_CONFIG:
        raise ValueError("Unsupported AES mode")

    with open(in_path, "rb") as fp:
        plaintext = fp.read(MAX_FILE_BYTES + 1)

    if len(plaintext) > MAX_FILE_BYTES:
        raise ValueError("Input exceeds laboratory size limit")

    cfg = MODE_CONFIG[mode]

    header = {
        "v": VERSION,
        "mode": mode,
        "alg": cfg["alg"],
        "padding": cfg["padding"],
        "key_id": key_id
    }

    if mode == "GCM":
        nonce = os.urandom(NONCE_BYTES_GCM)
        header["nonce"] = nonce.hex()
        raw_header = _pack_header(header)

        payload = AESGCM(enc_key).encrypt(
            nonce, plaintext, raw_header
        )

    else:
        iv = os.urandom(IV_BYTES_CBC)
        header["iv"] = iv.hex()
        raw_header = _pack_header(header)

        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(enc_key), modes.CBC(iv)
        )

        encryptor = cipher.encryptor()
        ciphertext = (
            encryptor.update(padded) + encryptor.finalize()
        )

        mac = hmac.HMAC(mac_key, hashes.SHA256())
        mac.update(raw_header)
        mac.update(ciphertext)

        payload = ciphertext + mac.finalize()

    _write_new(out_path, raw_header + payload)

    return cfg["tag_bytes"]


def decrypt_file(in_path, out_path,
                 enc_key, mac_key, key_id):

    _validate_keys(enc_key, mac_key)

    with open(in_path, "rb") as fp:
        header, raw_header = _read_header(fp)
        payload = fp.read(MAX_FILE_BYTES + 49)

    if len(payload) > MAX_FILE_BYTES + 48:
        raise ValueError("Container exceeds size limit")

    if header["key_id"] != key_id:
        raise ValueError("Key identifier mismatch")

    mode = header["mode"]

    try:
        if mode == "GCM":
            if len(payload) < 16:
                raise ValueError("Truncated GCM payload")

            nonce = bytes.fromhex(header["nonce"])

            plaintext = AESGCM(enc_key).decrypt(
                nonce, payload, raw_header
            )

        else:
            if len(payload) < 48:
                raise ValueError("Truncated CBC payload")

            ciphertext = payload[:-32]
            tag = payload[-32:]

            if len(ciphertext) % 16 != 0:
                raise ValueError("Invalid ciphertext length")

            mac = hmac.HMAC(mac_key, hashes.SHA256())
            mac.update(raw_header)
            mac.update(ciphertext)
            mac.verify(tag)

            iv = bytes.fromhex(header["iv"])

            cipher = Cipher(
                algorithms.AES(enc_key), modes.CBC(iv)
            )

            decryptor = cipher.decryptor()
            padded = (
                decryptor.update(ciphertext)
                + decryptor.finalize()
            )

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = (
                unpadder.update(padded)
                + unpadder.finalize()
            )

    except (InvalidTag, InvalidSignature):
        raise ValueError("Authentication failed") from None

    if len(plaintext) > MAX_FILE_BYTES:
        raise ValueError("Plaintext exceeds size limit")

    _write_new(out_path, plaintext)

    return mode

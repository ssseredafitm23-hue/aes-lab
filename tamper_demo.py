import secrets
import struct
import tempfile
from pathlib import Path

from key_manager import KeyManager
from crypto_aes import encrypt_file, decrypt_file


def mutate(data, part):
    modified = bytearray(data)

    header_size = struct.unpack(">H", data[4:6])[0]
    payload_start = 6 + header_size

    if part == "ciphertext":
        modified[payload_start] ^= 1

    elif part == "tag":
        modified[-1] ^= 1

    elif part == "header":
        marker = (
            b'"nonce":"' if b'"nonce":"' in data[:payload_start]
            else b'"iv":"'
        )

        pos = data.index(marker) + len(marker)

        modified[pos] = (
            ord("1") if modified[pos] == ord("0")
            else ord("0")
        )

    else:
        raise ValueError("Unknown test case")

    return bytes(modified)


def main():
    print("=== AES TAMPER DETECTION DEMO ===")
    password = secrets.token_urlsafe(24)
    passed = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        km = KeyManager(root / "keystore.json")
        source = root / "sample.txt"

        source.write_bytes(b"Synthetic AES integrity test")

        for mode in ("CBC-HMAC", "GCM"):
            print(f"\n=== {mode} ===")

            km.new_key(mode, password)

            meta, enc, mac = km.reserve_for_encryption(
                mode, password
            )

            original = root / f"{mode}.enc"

            encrypt_file(
                source, original, mode,
                enc, mac, meta["key_id"]
            )

            for part in ("ciphertext", "tag", "header"):
                damaged = root / f"{mode}-{part}.enc"
                restored = root / f"{mode}-{part}.dec"

                damaged.write_bytes(
                    mutate(original.read_bytes(), part)
                )

                try:
                    decrypt_file(
                        damaged, restored,
                        enc, mac, meta["key_id"]
                    )

                except ValueError as exc:
                    assert str(exc) == "Authentication failed"
                    assert not restored.exists()

                    print(f"[PASS] Modified {part}: {exc}")
                    print("       No plaintext output created")
                    passed += 1

                else:
                    raise AssertionError(
                        "Tampering was not detected"
                    )

    print(f"\nPassed tamper checks: {passed}/6")


if __name__ == "__main__":
    main()

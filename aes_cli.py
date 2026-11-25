import argparse
import shlex
import sys
import time
from pathlib import Path
from getpass import getpass

from config import ITERATIONS
from key_manager import KeyManager
from crypto_aes import (
    encrypt_file, decrypt_file, read_header,
    MODE_CONFIG, MAX_FILE_BYTES
)
from logger_setup import record_event, show_summary

MODES = {"cbc": "CBC-HMAC", "gcm": "GCM"}


def build_parser():
    parser = argparse.ArgumentParser(description="AES Security Lab")
    sub = parser.add_subparsers(dest="cmd", required=True)

    key = sub.add_parser("key", help="Key management")
    actions = key.add_subparsers(dest="action", required=True)

    new = actions.add_parser("new")
    new.add_argument("--label", required=True)
    actions.add_parser("list")

    enc = sub.add_parser("enc", help="Encrypt file")
    enc.add_argument("--in", dest="infile", required=True)
    enc.add_argument("--out", dest="outfile", required=True)
    enc.add_argument("--label", required=True)
    enc.add_argument("--mode", choices=MODES)

    dec = sub.add_parser("dec", help="Decrypt file")
    dec.add_argument("--in", dest="infile", required=True)
    dec.add_argument("--out", dest="outfile", required=True)

    sub.add_parser("settings", help="Show AES parameters")
    sub.add_parser("logs", help="Show security log summary")
    sub.add_parser("shell", help="Interactive mode")

    return parser


def check_paths(infile, outfile):
    source = Path(infile)
    target = Path(outfile)

    if not source.is_file():
        raise ValueError("Input file not found")

    if target.exists() or target.is_symlink():
        raise ValueError("Output file already exists")

    if not target.parent.is_dir():
        raise ValueError("Output directory not found")


def execute(args, active_mode, event):
    km = KeyManager()

    if args.cmd == "key":
        if args.action == "new":
            password = getpass("New password: ")
            confirm = getpass("Confirm password: ")

            if password != confirm:
                raise ValueError("Passwords do not match")

            meta = km.new_key(args.label, password)

            print("Key created:", meta["label"])
            print("Key ID:", meta["key_id"])
            print("Status: READY")

        elif args.action == "list":
            keys = km.list_keys()

            if not keys:
                print("No keys found")

            for meta in keys:
                status = (
                    "USED" if meta["uses"] else "READY"
                )
                print(
                    f'{meta["label"]}: {status} '
                    f'({meta["key_id"][:16]}...)'
                )

    elif args.cmd == "enc":
        event["mode"] = MODES[args.mode or active_mode]
        check_paths(args.infile, args.outfile)

        if Path(args.infile).stat().st_size > MAX_FILE_BYTES:
            raise ValueError("Input exceeds laboratory size limit")

        mode = MODES[args.mode or active_mode]
        password = getpass("Password: ")

        meta, enc_key, mac_key = km.reserve_for_encryption(
            args.label, password
        )

        tag_length = encrypt_file(
            args.infile, args.outfile, mode,
            enc_key, mac_key, meta["key_id"]
        )

        print("Encryption successful")
        print("Mode:", mode)
        print("Authentication tag:", tag_length, "bytes")
        print("Output:", args.outfile)

    elif args.cmd == "dec":
        check_paths(args.infile, args.outfile)
        header = read_header(args.infile)
        event["mode"] = header["mode"]

        meta = next(
            (k for k in km.list_keys()
             if k["key_id"] == header["key_id"]),
            None
        )

        if meta is None:
            raise ValueError("Matching key not found")

        password = getpass("Password: ")

        meta, enc_key, mac_key = km.derive_keypair(
            meta["label"], password
        )

        mode = decrypt_file(
            args.infile, args.outfile,
            enc_key, mac_key, meta["key_id"]
        )

        print("Decryption successful")
        print("Detected mode:", mode)
        print("Output:", args.outfile)

    elif args.cmd == "logs":
        show_summary()

    elif args.cmd == "settings":
        print("Active mode:", MODES[active_mode])
        print("AES key length: 256 bits")
        print("AES block size: 128 bits")
        print("PBKDF2 iterations:", ITERATIONS)
        print("CBC IV: 16 bytes")
        print("GCM nonce: 12 bytes")
        print("Maximum input: 128 MiB")

        for mode, cfg in MODE_CONFIG.items():
            print(
                f'{mode}: padding={cfg["padding"]}, '
                f'tag={cfg["tag_bytes"]} bytes'
            )


def run_command(args, active_mode="gcm"):
    started = time.perf_counter()
    event = {"mode": None}
    operation = args.cmd

    if args.cmd == "key":
        operation = "key." + args.action

    reasons = {
        "Invalid password or key metadata": "invalid_password",
        "Authentication failed": "authentication_failed",
        "Key identifier mismatch": "key_mismatch",
        "Matching key not found": "key_not_found",
        "Key reuse prohibited": "key_reuse",
        "Passwords do not match": "password_mismatch",
        "Password must contain at least 12 characters": "weak_password",
        "Output file already exists": "output_exists",
        "Input file not found": "input_not_found"
    }

    try:
        execute(args, active_mode, event)

        if args.cmd != "logs":
            record_event(
                operation, True,
                mode=event["mode"],
                reason="success",
                elapsed_ms=round(
                    (time.perf_counter() - started) * 1000, 3
                )
            )

        return 0

    except (ValueError, OSError, KeyError, TypeError) as exc:
        reason = reasons.get(
            str(exc), "invalid_input_or_container"
        )

        record_event(
            operation, False,
            mode=event["mode"],
            reason=reason,
            elapsed_ms=round(
                (time.perf_counter() - started) * 1000, 3
            )
        )

        print("ERROR:", exc, file=sys.stderr)
        return 1


def shell(parser):
    mode = "gcm"

    print("AES Security Lab — interactive mode")
    print("Commands: key, mode, enc, dec, settings, logs, help, exit")

    while True:
        try:
            tokens = shlex.split(input(f"[{mode}]> "))

            if not tokens:
                continue

            if tokens[0] in ("exit", "quit"):
                break

            if tokens[0] == "help":
                parser.print_help()
                continue

            if tokens[0] == "mode":
                if len(tokens) != 2 or tokens[1] not in MODES:
                    print("Usage: mode cbc | gcm")
                    continue

                mode = tokens[1]
                print("Active mode:", MODES[mode])
                record_event("mode.change", True, MODES[mode])
                continue

            if tokens[0] == "shell":
                print("Interactive mode already active")
                continue

            args = parser.parse_args(tokens)
            run_command(args, mode)

        except SystemExit:
            continue

        except ValueError as exc:
            print("ERROR:", exc)

        except (EOFError, KeyboardInterrupt):
            print()
            break

    print("Session closed")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "shell":
        shell(parser)
        return 0

    return run_command(args)


if __name__ == "__main__":
    sys.exit(main())

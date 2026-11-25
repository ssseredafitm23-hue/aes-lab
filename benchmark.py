import os
import sys
import csv
import json
import time
import filecmp
import resource
import tempfile
import subprocess
import statistics
from pathlib import Path

import psutil

from key_manager import KeyManager
from crypto_aes import encrypt_file, decrypt_file

SIZES = (1, 10, 100)
MODES = ("CBC-HMAC", "GCM")
REPEAT = 5
MIB = 1024 * 1024

# Synthetic benchmark password, not a real user secret
PASSWORD = "Benchmark-Demo-Password-2026"


def worker(operation, store, label, source, target, mode):
    km = KeyManager(store)
    process = psutil.Process()

    started = time.perf_counter()

    if operation == "enc":
        meta, enc, mac = km.reserve_for_encryption(
            label, PASSWORD
        )
    else:
        meta, enc, mac = km.derive_keypair(
            label, PASSWORD
        )

    kdf_time = time.perf_counter() - started

    baseline_rss = process.memory_info().rss / MIB

    cpu_start = time.process_time()
    wall_start = time.perf_counter()

    if operation == "enc":
        encrypt_file(
            source, target, mode,
            enc, mac, meta["key_id"]
        )
    else:
        detected = decrypt_file(
            source, target,
            enc, mac, meta["key_id"]
        )

        if detected != mode:
            raise RuntimeError("Unexpected mode")

    elapsed = time.perf_counter() - wall_start
    cpu_time = time.process_time() - cpu_start

    peak_rss = (
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        / 1024
    )

    print(json.dumps({
        "sec": elapsed,
        "cpu_ms": cpu_time * 1000,
        "cpu_pct": 100 * cpu_time / max(elapsed, 1e-9),
        "rss_mib": peak_rss,
        "baseline_rss_mib": baseline_rss,
        "key_setup_ms": kdf_time * 1000
    }))


def run_worker(operation, store, label,
               source, target, mode):

    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker", operation,
            str(store), label,
            str(source), str(target), mode
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return json.loads(result.stdout)


def generate_file(path, size_mib):
    with path.open("wb") as fp:
        for _ in range(size_mib):
            fp.write(os.urandom(MIB))


def save_results(rows):
    out = Path("outputs")
    out.mkdir(exist_ok=True)

    with (out / "bench.csv").open(
        "w", newline="", encoding="utf-8"
    ) as fp:
        writer = csv.DictWriter(
            fp, fieldnames=list(rows[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# AES benchmark results",
        "",
        "Median of 5 trials per configuration.",
        "Times include file I/O and authentication.",
        "Key setup is measured separately.",
        "CPU percent is relative to one logical CPU.",
        "Peak RSS includes process startup and key setup.",
        "",
        "| Size MiB | Mode | Enc ms | Dec ms | Enc MiB/s | Dec MiB/s | Enc CPU ms | Dec CPU ms | Enc CPU % | Dec CPU % | Enc RSS MiB | Dec RSS MiB | Enc key ms | Dec key ms | Verified |",
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"
    ]

    print("\n=== BENCHMARK SUMMARY (MEDIAN) ===")

    for size in SIZES:
        for mode in MODES:
            group = [
                r for r in rows
                if r["size_mib"] == size
                and r["mode"] == mode
            ]

            def med(field):
                return statistics.median(
                    r[field] for r in group
                )

            values = [
                med("enc_sec") * 1000,
                med("dec_sec") * 1000,
                med("enc_mib_s"),
                med("dec_mib_s"),
                med("enc_cpu_ms"),
                med("dec_cpu_ms"),
                med("enc_cpu_pct"),
                med("dec_cpu_pct"),
                med("enc_rss_mib"),
                med("dec_rss_mib"),
                med("enc_key_setup_ms"),
                med("dec_key_setup_ms")
            ]

            verified = all(
                r["verified"] for r in group
            )

            formatted = " | ".join(
                f"{v:.2f}" for v in values
            )

            lines.append(
                f"| {size} | {mode} | {formatted} | "
                f"{'PASS' if verified else 'FAIL'} |"
            )

            print(
                f"{size:3} MiB {mode:8} | "
                f"ENC {med('enc_mib_s'):8.2f} MiB/s | "
                f"DEC {med('dec_mib_s'):8.2f} MiB/s | "
                f"RSS {med('enc_rss_mib'):.1f}/"
                f"{med('dec_rss_mib'):.1f} MiB | "
                f"{'PASS' if verified else 'FAIL'}"
            )

    (out / "bench.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )


def main():
    rows = []

    print("=== AES PERFORMANCE BENCHMARK ===")
    print("Modes:", ", ".join(MODES))
    print("Sizes:", SIZES, "MiB")
    print("Repeats:", REPEAT)
    print("Logical CPUs:", psutil.cpu_count())
    print("RAM MiB:", round(
        psutil.virtual_memory().total / MIB
    ))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = root / "keystore.json"
        km = KeyManager(store)

        for size in SIZES:
            source = root / "source.bin"
            generate_file(source, size)

            for trial in range(1, REPEAT + 1):
                order = (
                    MODES if trial % 2
                    else MODES[::-1]
                )

                for mode in order:
                    label = f"bench-{size}-{mode}-{trial}"
                    km.new_key(label, PASSWORD)

                    encrypted = root / "test.enc"
                    restored = root / "test.dec"

                    enc = run_worker(
                        "enc", store, label,
                        source, encrypted, mode
                    )

                    dec = run_worker(
                        "dec", store, label,
                        encrypted, restored, mode
                    )

                    verified = filecmp.cmp(
                        source, restored, shallow=False
                    )

                    if not verified:
                        raise RuntimeError(
                            "Roundtrip verification failed"
                        )

                    row = {
                        "size_mib": size,
                        "mode": mode,
                        "trial": trial,
                        "verified": verified,
                        "encrypted_bytes": encrypted.stat().st_size
                    }

                    for prefix, metrics in (
                        ("enc", enc), ("dec", dec)
                    ):
                        for field, value in metrics.items():
                            row[f"{prefix}_{field}"] = value

                        row[f"{prefix}_mib_s"] = (
                            size / metrics["sec"]
                        )

                    rows.append(row)

                    print(
                        f"[PASS] {size} MiB | "
                        f"{mode} | Trial {trial}/{REPEAT}",
                        flush=True
                    )

                    encrypted.unlink()
                    restored.unlink()

    save_results(rows)

    print("\nCompleted cycles:", len(rows))
    print("All restored files verified:", all(
        row["verified"] for row in rows
    ))
    print("Results: outputs/bench.csv")
    print("Summary: outputs/bench.md")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(*sys.argv[2:])
    else:
        main()

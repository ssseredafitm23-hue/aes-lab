# AES benchmark results

Median of 5 trials per configuration.
Times include file I/O and authentication.
Key setup is measured separately.
CPU percent is relative to one logical CPU.
Peak RSS includes process startup and key setup.

| Size MiB | Mode | Enc ms | Dec ms | Enc MiB/s | Dec MiB/s | Enc CPU ms | Dec CPU ms | Enc CPU % | Dec CPU % | Enc RSS MiB | Dec RSS MiB | Enc key ms | Dec key ms | Verified |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | CBC-HMAC | 8.00 | 7.34 | 125.00 | 136.30 | 8.01 | 7.35 | 100.11 | 100.03 | 38.07 | 37.88 | 718.01 | 703.14 | PASS |
| 1 | GCM | 3.39 | 2.61 | 295.27 | 383.70 | 3.39 | 2.61 | 100.21 | 100.25 | 36.34 | 36.47 | 702.89 | 695.71 | PASS |
| 10 | CBC-HMAC | 53.44 | 45.60 | 187.12 | 219.29 | 53.41 | 45.42 | 99.97 | 99.97 | 83.16 | 82.79 | 699.02 | 695.09 | PASS |
| 10 | GCM | 14.01 | 11.70 | 713.99 | 854.40 | 14.02 | 11.69 | 100.09 | 100.09 | 62.79 | 52.86 | 706.27 | 701.04 | PASS |
| 100 | CBC-HMAC | 473.03 | 400.99 | 211.40 | 249.38 | 473.15 | 401.07 | 99.92 | 99.86 | 533.06 | 532.79 | 697.63 | 699.29 | PASS |
| 100 | GCM | 118.07 | 97.13 | 846.95 | 1029.54 | 117.17 | 97.07 | 99.88 | 100.02 | 332.86 | 232.88 | 690.55 | 692.49 | PASS |

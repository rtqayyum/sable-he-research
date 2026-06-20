#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from time import perf_counter

from sable import arithmetic as A
from sable.params import PRESETS
from sable.sable import compact_c7_screened, decrypt_c7_screened, encrypt, expand, keygen_c7_screened


def main() -> None:
    params = PRESETS["c7_screened_toy_clean"]
    kp = keygen_c7_screened(params, seed=424242, block_size=4, target_size=7, min_relation_weight=5)

    def enc(v: int, seed: int):
        return expand(kp, encrypt(kp, v % params.q, seed=seed))

    def dec(ct):
        return decrypt_c7_screened(kp, compact_c7_screened(kp, ct))

    X, Y, Z, W = enc(5, 1), enc(3, 2), enc(2, 3), enc(6, 4)
    q = params.q
    cases = [
        ("add", lambda: A.add(X, Y), (5 + 3) % q),
        ("sub", lambda: A.sub(X, Y), (5 - 3) % q),
        ("neg", lambda: A.neg(X), (-5) % q),
        ("scalar_mul", lambda: A.scalar_mul(X, 4), (4 * 5) % q),
        ("add_const", lambda: A.add_const(X, 6), (5 + 6) % q),
        ("mul", lambda: A.mul(X, Y), (5 * 3) % q),
        ("square", lambda: A.square(Y), (3 * 3) % q),
        ("poly2", lambda: A.poly_eval(X, [3, 2, 5]), (3 + 2 * 5 + 5 * 5 * 5) % q),
        ("dot4", lambda: A.dot_public([1, 2, 3, 4], [X, Y, Z, W], constant=6), (5 + 6 + 6 + 24 + 6) % q),
        ("quadratic_form", lambda: A.add_const(A.add(A.mul(X, Y), A.mul(Z, W)), 5), (5 * 3 + 2 * 6 + 5) % q),
        ("boolean_and", lambda: A.gate_and(enc(1, 10), enc(0, 11)), 0),
        ("boolean_or", lambda: A.gate_or(enc(1, 12), enc(0, 13)), 1),
        ("boolean_xor", lambda: A.gate_xor(enc(1, 14), enc(0, 15)), 1),
        ("boolean_not", lambda: A.gate_not(enc(0, 16)), 1),
    ]
    rows = []
    for name, fn, expected in cases:
        t0 = perf_counter()
        ct = fn()
        value = dec(ct)
        elapsed_ms = (perf_counter() - t0) * 1000.0
        rows.append({"operation": name, "expected": expected, "decrypted": value, "passed": value == expected, "elapsed_ms_python_toy": elapsed_ms})
    out_dir = Path("docs/generated")
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "c7_final_arithmetic.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "c7_final_arithmetic.json").write_text(json.dumps(rows, indent=2))
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Microbenchmark high-level SABLE-C4 arithmetic operations.

The benchmark measures the pure-Python research prototype only.  It is not a
claim about optimized cryptographic performance.  It reports both evaluation
latency and evaluation+compaction+decryption latency on small toy parameters.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable import operations as ops
from sable.params import PRESETS
from sable.sable import compact_basis_c4, decrypt_basis_c4, encrypt, expand, keygen_basis_c4


@dataclass(frozen=True)
class BenchRow:
    operation: str
    preset: str
    q: int
    repetitions: int
    median_eval_ms: float
    mean_eval_ms: float
    median_eval_compact_decrypt_ms: float
    mean_eval_compact_decrypt_ms: float
    expected: int
    verified: bool
    note: str


def _median(xs: list[float]) -> float:
    return statistics.median(xs) if xs else 0.0


def _mean(xs: list[float]) -> float:
    return statistics.mean(xs) if xs else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark SABLE-C4 arithmetic operation microbenchmarks")
    parser.add_argument("--preset", default="c4_projective_toy_clean", choices=sorted(PRESETS))
    parser.add_argument("--repetitions", type=int, default=50)
    parser.add_argument("--csv-out", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    params = PRESETS[args.preset]
    kp = keygen_basis_c4(params, seed=424242, block_size=params.c2_block_size, mode="projective")
    q = params.q
    a, b = 5 % q, 3 % q
    if a == 0:
        a = 1
    if b == 0:
        b = 2
    A = expand(kp, encrypt(kp, a, seed=101))
    B = expand(kp, encrypt(kp, b, seed=102))
    X1 = expand(kp, encrypt(kp, 1, seed=103))
    X0 = expand(kp, encrypt(kp, 0, seed=104))

    def dec(ct):
        return decrypt_basis_c4(kp, compact_basis_c4(kp, ct)) % q

    operations: list[tuple[str, Callable[[], object], int, str]] = [
        ("zero", lambda: ops.zero_like(A), 0, "public zero in expanded form"),
        ("one", lambda: ops.one_like(A), 1, "public one in expanded form"),
        ("const_4", lambda: ops.const_like(A, 4), 4, "public constant beta I"),
        ("add", lambda: ops.add(A, B), a + b, "encrypted addition"),
        ("sub", lambda: ops.sub(A, B), a - b, "encrypted subtraction"),
        ("neg", lambda: ops.neg(A), -a, "encrypted negation"),
        ("scalar_mul_4", lambda: ops.scalar_mul(A, 4), 4 * a, "public scalar multiplication"),
        ("add_plain_6", lambda: ops.add_plain(A, 6), a + 6, "add public plaintext"),
        ("mul", lambda: ops.mul(A, B), a * b, "encrypted multiplication"),
        ("square", lambda: ops.square(A), a * a, "encrypted square"),
        ("pow3", lambda: ops.pow_plain(A, 3), a**3, "public exponentiation by 3"),
        ("inverse_nonzero", lambda: ops.inverse_nonzero(A), pow(a, q - 2, q), "Fermat inverse; small q only"),
        ("div_nonzero", lambda: ops.div_nonzero(A, B), a * pow(b, q - 2, q), "nonzero division by inverse"),
        ("bool_not_1", lambda: ops.gate_not(X1), 0, "NOT(1) over bit encoding"),
        ("bool_and_10", lambda: ops.gate_and(X1, X0), 0, "AND over bit encoding"),
        ("bool_or_10", lambda: ops.gate_or(X1, X0), 1, "OR over bit encoding"),
        ("bool_xor_10", lambda: ops.gate_xor(X1, X0), 1, "XOR over bit encoding"),
    ]

    rows: list[BenchRow] = []
    for name, fn, expected, note in operations:
        eval_ms: list[float] = []
        full_ms: list[float] = []
        verified = True
        expected_mod = expected % q
        # warmup
        ct = fn()
        got = dec(ct)  # type: ignore[arg-type]
        if got != expected_mod:
            verified = False
        for _ in range(args.repetitions):
            start = time.perf_counter_ns()
            ct = fn()
            mid = time.perf_counter_ns()
            got = dec(ct)  # type: ignore[arg-type]
            end = time.perf_counter_ns()
            if got != expected_mod:
                verified = False
            eval_ms.append((mid - start) / 1_000_000.0)
            full_ms.append((end - start) / 1_000_000.0)
        rows.append(
            BenchRow(
                operation=name,
                preset=params.name,
                q=q,
                repetitions=args.repetitions,
                median_eval_ms=_median(eval_ms),
                mean_eval_ms=_mean(eval_ms),
                median_eval_compact_decrypt_ms=_median(full_ms),
                mean_eval_compact_decrypt_ms=_mean(full_ms),
                expected=expected_mod,
                verified=verified,
                note=note,
            )
        )

    if args.csv_out:
        args.csv_out.parent.mkdir(parents=True, exist_ok=True)
        with args.csv_out.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
            writer.writeheader()
            writer.writerows(asdict(r) for r in rows)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps([asdict(r) for r in rows], indent=2))
    if args.json:
        print(json.dumps([asdict(r) for r in rows], indent=2))
    else:
        for r in rows:
            print(
                f"{r.operation:16s} eval_med={r.median_eval_ms:9.4f} ms  "
                f"eval+compact+dec_med={r.median_eval_compact_decrypt_ms:9.4f} ms  verified={r.verified}"
            )


if __name__ == "__main__":
    main()

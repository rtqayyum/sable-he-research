#!/usr/bin/env python3
"""Micro-benchmark the current SABLE-HE Python prototype.

This measures this repository's pure-Python research prototype only.  It is not
an optimized implementation and should not be compared directly to optimized
C/C++ FHE libraries.  The output is useful for tracking bottlenecks as the
prototype evolves.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.params import PRESETS
from sable.sable import compact, decrypt, encrypt, eval_add, eval_mul, expand, keygen


def median(xs: list[float]) -> float:
    return statistics.median(xs) if xs else 0.0


def bench_preset(name: str, trials: int, seed: int, oriented: bool = False) -> dict:
    params = PRESETS[name]
    rng = random.Random(seed)
    t0 = time.perf_counter()
    kp = keygen(params, seed=seed)
    keygen_s = time.perf_counter() - t0

    timings = {
        "encrypt_s": [],
        "expand_s": [],
        "eval_add_s": [],
        "eval_mul_s": [],
        "compact_s": [],
        "decrypt_s": [],
        "end_to_end_mul_s": [],
    }
    correctness = 0
    max_support = 0

    for trial in range(trials):
        x = rng.randrange(params.q)
        y = rng.randrange(params.q)
        trial_seed = seed * 100000 + trial * 10

        start = time.perf_counter()
        cx0 = encrypt(kp, x, seed=trial_seed + 1)
        cy0 = encrypt(kp, y, seed=trial_seed + 2)
        timings["encrypt_s"].append(time.perf_counter() - start)

        start = time.perf_counter()
        cx = expand(kp, cx0)
        cy = expand(kp, cy0)
        timings["expand_s"].append(time.perf_counter() - start)

        start = time.perf_counter()
        _ = eval_add(cx, cy)
        timings["eval_add_s"].append(time.perf_counter() - start)

        start_total = time.perf_counter()
        start = time.perf_counter()
        cxy = eval_mul(cx, cy, oriented=oriented)
        timings["eval_mul_s"].append(time.perf_counter() - start)
        max_support = max(max_support, max(C.max_row_support() for C in cxy))

        start = time.perf_counter()
        z = compact(kp, cxy)
        timings["compact_s"].append(time.perf_counter() - start)

        start = time.perf_counter()
        got = decrypt(kp, z)
        timings["decrypt_s"].append(time.perf_counter() - start)
        timings["end_to_end_mul_s"].append(time.perf_counter() - start_total)
        correctness += int(got == (x * y) % params.q)

    med = {key: median(values) for key, values in timings.items()}
    return {
        "preset": name,
        "trials": trials,
        "oriented_mul": oriented,
        "keygen_s": keygen_s,
        "median_timings_s": med,
        "successes": correctness,
        "failures": trials - correctness,
        "success_rate": correctness / trials if trials else None,
        "max_support_seen_after_mul": max_support,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--presets", nargs="*", default=["toy_clean", "toy_noisy", "toy_depth2"], choices=sorted(PRESETS))
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument("--oriented", action="store_true")
    parser.add_argument("--csv", type=Path, default=None)
    args = parser.parse_args()

    results = [bench_preset(name, args.trials, args.seed + i, oriented=args.oriented) for i, name in enumerate(args.presets)]
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for result in results:
            row = {k: v for k, v in result.items() if k != "median_timings_s"}
            row.update({f"median_{k}": v for k, v in result["median_timings_s"].items()})
            rows.append(row)
        with args.csv.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps({"results": results}, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Depth sweep for balanced product circuits."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.params import PRESETS
from sable.sable import compact, decrypt, encrypt, eval_mul, expand, keygen


def encrypt_expand(kp, value: int, seed: int):
    return expand(kp, encrypt(kp, value, seed=seed))


def product_tree(kp, values: list[int], seed_base: int):
    cts = [encrypt_expand(kp, x, seed_base + i) for i, x in enumerate(values)]
    while len(cts) > 1:
        nxt = []
        for i in range(0, len(cts), 2):
            if i + 1 < len(cts):
                nxt.append(eval_mul(cts[i], cts[i + 1]))
            else:
                nxt.append(cts[i])
        cts = nxt
    return cts[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="toy_depth2", choices=sorted(PRESETS))
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--trials", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    kp = keygen(PRESETS[args.preset], seed=args.seed)
    rng = random.Random(args.seed + 2024)
    rows = []

    for depth in range(args.max_depth + 1):
        variables = 2**depth
        successes = 0
        max_support_seen = 0
        for trial in range(args.trials):
            values = [rng.randrange(kp.params.q) for _ in range(variables)]
            expected = 1
            for x in values:
                expected = (expected * x) % kp.params.q
            ct = product_tree(kp, values, seed_base=500000 + 1000 * depth + 100 * trial)
            max_support_seen = max(max_support_seen, max(C.max_row_support() for C in ct))
            got = decrypt(kp, compact(kp, ct))
            if got == expected:
                successes += 1
        rows.append({
            "depth": depth,
            "variables": variables,
            "trials": args.trials,
            "successes": successes,
            "failures": args.trials - successes,
            "success_rate": successes / args.trials if args.trials else None,
            "max_row_support_seen": max_support_seen,
        })

    print(json.dumps({"preset": args.preset, "rows": rows}, indent=2))


if __name__ == "__main__":
    main()

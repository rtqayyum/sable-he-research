#!/usr/bin/env python3
"""Monte Carlo correctness checks for small SABLE-HE circuits."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.params import PRESETS
from sable.sable import compact, decrypt, encrypt, eval_add, eval_mul, expand, keygen


def encrypt_expand(kp, value: int, seed: int):
    return expand(kp, encrypt(kp, value, seed=seed))


def evaluate_function(kp, name: str, rng: random.Random, seed_base: int):
    q = kp.params.q
    if name == "add":
        x, y = rng.randrange(q), rng.randrange(q)
        cx = encrypt_expand(kp, x, seed_base + 1)
        cy = encrypt_expand(kp, y, seed_base + 2)
        out = eval_add(cx, cy)
        expected = (x + y) % q
        return out, expected
    if name == "mul":
        x, y = rng.randrange(q), rng.randrange(q)
        cx = encrypt_expand(kp, x, seed_base + 1)
        cy = encrypt_expand(kp, y, seed_base + 2)
        out = eval_mul(cx, cy)
        expected = (x * y) % q
        return out, expected
    if name == "xy_plus_z":
        x, y, z = rng.randrange(q), rng.randrange(q), rng.randrange(q)
        cx = encrypt_expand(kp, x, seed_base + 1)
        cy = encrypt_expand(kp, y, seed_base + 2)
        cz = encrypt_expand(kp, z, seed_base + 3)
        out = eval_add(eval_mul(cx, cy), cz)
        expected = (x * y + z) % q
        return out, expected
    if name == "quad_sum":
        x1, x2, x3, x4 = [rng.randrange(q) for _ in range(4)]
        c1 = encrypt_expand(kp, x1, seed_base + 1)
        c2 = encrypt_expand(kp, x2, seed_base + 2)
        c3 = encrypt_expand(kp, x3, seed_base + 3)
        c4 = encrypt_expand(kp, x4, seed_base + 4)
        out = eval_add(eval_mul(c1, c2), eval_mul(c3, c4))
        expected = (x1 * x2 + x3 * x4) % q
        return out, expected
    if name == "boolean_or":
        x, y = rng.randrange(2), rng.randrange(2)
        cx = encrypt_expand(kp, x, seed_base + 1)
        cy = encrypt_expand(kp, y, seed_base + 2)
        # OR(x,y)=x+y-xy over F_q.
        xy = eval_mul(cx, cy)
        x_plus_y = eval_add(cx, cy)
        neg_xy = [C.scale(q - 1) for C in xy]
        out = eval_add(x_plus_y, neg_xy)
        expected = int(bool(x or y))
        return out, expected
    if name == "boolean_xor":
        x, y = rng.randrange(2), rng.randrange(2)
        cx = encrypt_expand(kp, x, seed_base + 1)
        cy = encrypt_expand(kp, y, seed_base + 2)
        # XOR(x,y)=x+y-2xy over odd-characteristic F_q.
        xy = eval_mul(cx, cy)
        x_plus_y = eval_add(cx, cy)
        minus_2xy = [C.scale(q - 2) for C in xy]
        out = eval_add(x_plus_y, minus_2xy)
        expected = x ^ y
        return out, expected
    raise ValueError(f"unknown function: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--function", default="mul", choices=["add", "mul", "xy_plus_z", "quad_sum", "boolean_or", "boolean_xor"])
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    params = PRESETS[args.preset]
    kp = keygen(params, seed=args.seed)
    rng = random.Random(args.seed + 999)

    successes = 0
    failures = []
    max_support_seen = 0
    for trial in range(args.trials):
        out_ct, expected = evaluate_function(kp, args.function, rng, seed_base=100000 + 100 * trial)
        max_support_seen = max(max_support_seen, max(C.max_row_support() for C in out_ct))
        got = decrypt(kp, compact(kp, out_ct))
        if got == expected:
            successes += 1
        else:
            failures.append({"trial": trial, "expected": expected, "got": got})

    summary = {
        "preset": args.preset,
        "function": args.function,
        "trials": args.trials,
        "successes": successes,
        "failures": args.trials - successes,
        "success_rate": successes / args.trials if args.trials else None,
        "max_row_support_seen": max_support_seen,
        "first_failures": failures[:10],
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

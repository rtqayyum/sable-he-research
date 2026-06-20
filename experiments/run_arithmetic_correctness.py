"""Monte Carlo validation for SABLE arithmetic and Boolean operations."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from sable import PRESETS
from sable import arithmetic as arith
from sable.sable import compact_basis_c4, decrypt_basis_c4, encrypt, expand, keygen_basis_c4


def _enc_exp(kp, x: int, seed: int):
    return expand(kp, encrypt(kp, x, seed=seed))


def _dec(kp, ct) -> int:
    return decrypt_basis_c4(kp, compact_basis_c4(kp, ct))


def run_trial(kp, rng: random.Random, trial: int) -> dict:
    q = kp.params.q
    x = rng.randrange(q)
    y = rng.randrange(q)
    z = rng.randrange(q)
    X = _enc_exp(kp, x, 1000 + trial * 5)
    Y = _enc_exp(kp, y, 1001 + trial * 5)
    Z = _enc_exp(kp, z, 1002 + trial * 5)
    checks: dict[str, tuple[int, int]] = {}
    checks["add"] = (_dec(kp, arith.eval_add(X, Y)), (x + y) % q)
    checks["sub"] = (_dec(kp, arith.eval_sub(X, Y)), (x - y) % q)
    checks["neg"] = (_dec(kp, arith.eval_neg(X)), (-x) % q)
    checks["scalar_mul"] = (_dec(kp, arith.eval_scalar(X, 3)), (3 * x) % q)
    checks["add_const"] = (_dec(kp, arith.eval_add_const(X, 5)), (x + 5) % q)
    checks["linear_combination"] = (_dec(kp, arith.eval_linear_combination([(2, X), (3, Y), (4, Z)], constant=6)), (2*x + 3*y + 4*z + 6) % q)
    checks["mul"] = (_dec(kp, arith.eval_mul(X, Y)), (x * y) % q)
    checks["square"] = (_dec(kp, arith.eval_square(X)), (x * x) % q)
    checks["poly2"] = (_dec(kp, arith.eval_poly(X, [5, 3, 1])), (x*x + 3*x + 5) % q)
    # Keep power depth low for noisy presets.
    checks["cube"] = (_dec(kp, arith.eval_power(X, 3)), pow(x, 3, q))
    ok = {name: got == expected for name, (got, expected) in checks.items()}
    return {
        "trial": trial,
        "x": x,
        "y": y,
        "z": z,
        "checks": {name: {"got": got, "expected": expected, "ok": ok[name]} for name, (got, expected) in checks.items()},
        "ok": all(ok.values()),
    }


def run_boolean_trial(kp, trial: int) -> dict:
    rows = []
    for x in [0, 1]:
        for y in [0, 1]:
            X = _enc_exp(kp, x, 2000 + trial * 20 + x * 2 + y)
            Y = _enc_exp(kp, y, 2010 + trial * 20 + x * 2 + y)
            values = {
                "not_x": (_dec(kp, arith.bool_not(X)), 1 - x),
                "and": (_dec(kp, arith.bool_and(X, Y)), x & y),
                "or": (_dec(kp, arith.bool_or(X, Y)), x | y),
                "xor": (_dec(kp, arith.bool_xor(X, Y)), x ^ y),
            }
            rows.append({
                "x": x,
                "y": y,
                "checks": {name: {"got": got, "expected": exp, "ok": got == exp} for name, (got, exp) in values.items()},
                "ok": all(got == exp for got, exp in values.values()),
            })
    return {"trial": trial, "rows": rows, "ok": all(row["ok"] for row in rows)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="c4_projective_toy_clean", choices=sorted(PRESETS))
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--seed", type=int, default=9876)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    kp = keygen_basis_c4(PRESETS[args.preset], seed=args.seed)
    trials = [run_trial(kp, rng, i) for i in range(args.trials)]
    bool_trials = [run_boolean_trial(kp, i) for i in range(args.trials)]
    report = {
        "preset": args.preset,
        "trials": args.trials,
        "arithmetic_successes": sum(t["ok"] for t in trials),
        "boolean_successes": sum(t["ok"] for t in bool_trials),
        "arithmetic": trials,
        "boolean": bool_trials,
        "note": "toy validation; noisy parameters have nonzero decryption-failure probability",
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

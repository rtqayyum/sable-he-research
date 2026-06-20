#!/usr/bin/env python3
"""End-to-end correctness check for C4 projective compaction."""

from __future__ import annotations

import json
from sable.params import PRESETS
from sable.sable import compact_basis_c4, decrypt_basis_c4, direct_decrypt_gsw, encrypt, eval_add, eval_mul, expand, keygen_basis_c4


def run_trial(seed: int) -> dict[str, int]:
    params = PRESETS["c2_toy_clean"]
    kp = keygen_basis_c4(params, seed=seed, block_size=2, max_terms_per_block=1, mode="projective")
    x, y, z = 2, 3, 4
    X = expand(kp, encrypt(kp, x, seed=seed + 1))
    Y = expand(kp, encrypt(kp, y, seed=seed + 2))
    Z = expand(kp, encrypt(kp, z, seed=seed + 3))
    F = eval_add(eval_mul(X, Y), Z)
    direct = direct_decrypt_gsw(kp, F)
    compact = compact_basis_c4(kp, F)
    dec = decrypt_basis_c4(kp, compact)
    expected = (x * y + z) % params.q
    return {"expected": expected, "direct": direct, "c4": dec}


def main() -> None:
    trials = [run_trial(1000 + i) for i in range(12)]
    ok = all(t["expected"] == t["direct"] == t["c4"] for t in trials)
    print(json.dumps({"ok": ok, "trials": trials}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

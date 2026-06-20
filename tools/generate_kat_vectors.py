#!/usr/bin/env python3
"""Generate small deterministic KAT-style vectors for the SABLE research prototype.

These are toy vectors for regression testing, not security-grade validation
vectors. They record plaintext outputs and SHA-256 digests of deterministic key,
ciphertext, and compacted-ciphertext representations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from sable import arithmetic as A
from sable.params import PRESETS
from sable.sable import (
    compact_c7,
    decrypt_c7,
    encrypt,
    expand,
    keygen_c7,
)


def normalize(obj: Any) -> Any:
    if is_dataclass(obj):
        return normalize(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): normalize(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [normalize(v) for v in obj]
    return obj


def digest(obj: Any) -> str:
    data = json.dumps(normalize(obj), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def c7_eval(params_name: str, key_seed: int, x_seed: int, y_seed: int, x: int, y: int) -> dict[str, Any]:
    params = PRESETS[params_name]
    kp = keygen_c7(params, seed=key_seed, mode="coordinate")
    ctx = expand(kp, encrypt(kp, x, seed=x_seed))
    cty = expand(kp, encrypt(kp, y, seed=y_seed))

    cases = {}
    operations = {
        "add": A.add(ctx, cty),
        "sub": A.sub(ctx, cty),
        "neg_x": A.neg(ctx),
        "scalar_3_x": A.scalar_mul(ctx, 3),
        "mul": A.mul(ctx, cty),
        "square_x": A.square(ctx),
        "xor_bit": A.gate_xor(ctx, cty),
        "or_bit": A.gate_or(ctx, cty),
        "and_bit": A.gate_and(ctx, cty),
    }
    expected = {
        "add": (x + y) % params.q,
        "sub": (x - y) % params.q,
        "neg_x": (-x) % params.q,
        "scalar_3_x": (3 * x) % params.q,
        "mul": (x * y) % params.q,
        "square_x": (x * x) % params.q,
        "xor_bit": (x + y - 2 * x * y) % params.q,
        "or_bit": (x + y - x * y) % params.q,
        "and_bit": (x * y) % params.q,
    }
    for name, expanded in operations.items():
        compacted = compact_c7(kp, expanded)
        observed = decrypt_c7(kp, compacted)
        cases[name] = {
            "expected": expected[name],
            "observed": observed,
            "expanded_digest": digest(expanded),
            "compact_digest": digest(compacted),
        }
    return {
        "suite": "sable-c7-toy-clean-kat",
        "warning": "toy regression vector only, not a security validation vector",
        "params": normalize(params),
        "seeds": {"key": key_seed, "x": x_seed, "y": y_seed},
        "plaintexts": {"x": x, "y": y},
        "public_key_digest": digest(kp.expansion_key),
        "c7_basis_digest": digest(kp.compaction_basis_c7),
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("vectors/sable_c7_toy_clean_kat.json"))
    parser.add_argument("--params", default="c7_standard_toy_clean")
    parser.add_argument("--key-seed", type=int, default=111)
    parser.add_argument("--x-seed", type=int, default=222)
    parser.add_argument("--y-seed", type=int, default=333)
    parser.add_argument("--x", type=int, default=1)
    parser.add_argument("--y", type=int, default=0)
    args = parser.parse_args()
    payload = c7_eval(args.params, args.key_seed, args.x_seed, args.y_seed, args.x, args.y)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

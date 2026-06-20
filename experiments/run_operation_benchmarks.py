"""Measure pure-Python SABLE operation timings and emit proxy comparisons."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from pathlib import Path

from sable import PRESETS
from sable import arithmetic as arith
from sable.operation_profiles import PROFILES, compare_operation, support_table_as_dicts
from sable.sable import compact_basis_c4, decrypt_basis_c4, encrypt, expand, keygen_basis_c4


def _enc_exp(kp, x: int, seed: int):
    return expand(kp, encrypt(kp, x, seed=seed))


def operation_fn(name, X, Y):
    if name == "add":
        return arith.eval_add(X, Y)
    if name == "sub":
        return arith.eval_sub(X, Y)
    if name == "scalar_mul":
        return arith.eval_scalar(X, 5)
    if name == "mul":
        return arith.eval_mul(X, Y)
    if name == "square":
        return arith.eval_square(X)
    if name == "poly2":
        return arith.eval_poly(X, [5, 3, 1])
    if name == "poly3":
        return arith.eval_poly(X, [4, 3, 2, 1])
    if name == "bool_not":
        return arith.bool_not(X)
    if name == "bool_and":
        return arith.bool_and(X, Y)
    if name == "bool_or":
        return arith.bool_or(X, Y)
    if name == "bool_xor":
        return arith.bool_xor(X, Y)
    if name == "quadratic4":
        # Reuse X,Y as four product terms for a deterministic microbenchmark.
        return arith.eval_add(arith.eval_add(arith.eval_mul(X, Y), arith.eval_mul(X, X)), arith.eval_add(arith.eval_mul(Y, Y), arith.eval_mul(Y, X)))
    raise KeyError(name)


def bench_one(kp, name: str, repeats: int) -> dict:
    X = _enc_exp(kp, 2 % kp.params.q, 3101)
    Y = _enc_exp(kp, 3 % kp.params.q, 3102)
    # Warmup.
    out = operation_fn(name, X, Y)
    times = []
    comp_times = []
    dec_times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        out = operation_fn(name, X, Y)
        t1 = time.perf_counter()
        compact = compact_basis_c4(kp, out)
        t2 = time.perf_counter()
        value = decrypt_basis_c4(kp, compact)
        t3 = time.perf_counter()
        times.append(t1 - t0)
        comp_times.append(t2 - t1)
        dec_times.append(t3 - t2)
    prof = arith.active_profile(out)
    return {
        "operation": name,
        "eval_seconds_median": statistics.median(times),
        "eval_seconds_min": min(times),
        "compact_seconds_median": statistics.median(comp_times),
        "decrypt_seconds_median": statistics.median(dec_times),
        "sample_decryption": value,
        "expanded_profile": prof,
        "proxy_comparison": compare_operation(kp.params, PROFILES[name]),
    }


def flatten(row: dict) -> dict:
    pc = row["proxy_comparison"]
    op = pc["operation"]
    s = pc["sable_c4"]
    tfhe = pc["existing_method_proxies"]["TFHE_FHEW"]
    bfv = pc["existing_method_proxies"]["BFV_BGV"]
    return {
        "operation": row["operation"],
        "additions": op["additions"],
        "multiplications": op["multiplications"],
        "depth": op["multiplicative_depth"],
        "eval_seconds_median": row["eval_seconds_median"],
        "compact_seconds_median": row["compact_seconds_median"],
        "decrypt_seconds_median": row["decrypt_seconds_median"],
        "sable_sparse_proxy": s["sparse_field_operation_proxy"],
        "sable_failure_bound": s["estimated_failure_bound"],
        "tfhe_gate_proxy": tfhe["gate_or_bootstrap_proxy"],
        "bfv_bgv_additions": bfv["ciphertext_additions"],
        "bfv_bgv_multiplications": bfv["ciphertext_multiplications"],
        "max_row_support": row["expanded_profile"]["max_row_support"],
        "total_nnz": row["expanded_profile"]["total_nnz"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="c4_projective_toy_clean", choices=sorted(PRESETS))
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--csv-out", type=Path, default=None)
    args = parser.parse_args()
    kp = keygen_basis_c4(PRESETS[args.preset], seed=4242)
    rows = [bench_one(kp, name, args.repeats) for name in PROFILES]
    report = {
        "preset": args.preset,
        "repeats": args.repeats,
        "support_table": support_table_as_dicts(),
        "rows": rows,
        "warning": "Pure-Python SABLE timings are research-prototype timings. Existing methods are proxy operation counts unless external OpenFHE/SEAL/TFHE-rs benchmarks are run separately.",
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True))
    if args.csv_out:
        args.csv_out.parent.mkdir(parents=True, exist_ok=True)
        flat = [flatten(row) for row in rows]
        with args.csv_out.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(flat[0].keys()))
            writer.writeheader()
            writer.writerows(flat)
    print(json.dumps({"preset": args.preset, "rows": [flatten(r) for r in rows]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

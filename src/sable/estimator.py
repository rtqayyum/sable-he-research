"""Correctness and size estimator for the SABLE-HE validation prototype."""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass

from .field import majority_failure_bound, qary_piling_up, repetition_failure_bound
from .params import PRESETS, SableParams
from .attacks import security_report


@dataclass(frozen=True)
class Quality:
    row_support: int
    error_probability: float


def fresh_quality(params: SableParams) -> Quality:
    w0 = (params.k + 1) ** 2
    eps0 = min(1.0, (params.k + 2) * params.eta)
    return Quality(w0, eps0)


def add_quality(a: Quality, b: Quality) -> Quality:
    return Quality(a.row_support + b.row_support, min(1.0, a.error_probability + b.error_probability))


def mul_quality(left: Quality, right: Quality) -> Quality:
    eps = left.error_probability + left.row_support * right.error_probability
    return Quality(left.row_support * right.row_support, min(1.0, eps))


def balanced_product_quality(params: SableParams, depth: int) -> Quality:
    if depth < 0:
        raise ValueError("depth must be nonnegative")
    q = fresh_quality(params)
    for _ in range(depth):
        q = mul_quality(q, q)
    return q


def estimate(params: SableParams, depth: int = 1, additions: int = 1, target_bits: int = 128) -> dict:
    """Estimate correctness and sizes for a balanced product of depth `depth`.

    `additions` is a conservative multiplier for final error after a sum of
    similarly shaped terms.
    """
    N = params.N
    fresh = fresh_quality(params)
    quality = balanced_product_quality(params, depth)
    eps_f = min(1.0, max(1, additions) * quality.error_probability)
    B = min(N, quality.row_support)
    eta_comp = qary_piling_up(params.q, params.eta_c, B)
    comp_fail = repetition_failure_bound(params.m_c, eta_comp)
    per_replica_failure = min(1.0, eps_f + comp_fail)
    final_failure = majority_failure_bound(params.replicas, per_replica_failure)

    input_ct_entries = params.replicas * (params.k + 1)
    expansion_key_entries = N * N * (params.k + 1)
    compaction_key_field_entries = N * params.m_c * (params.n_c + 1)
    expanded_entries_fresh = params.replicas * N * fresh.row_support
    expanded_entries_final = params.replicas * N * min(N, quality.row_support)
    multiplication_cost_proxy = N * quality.row_support * quality.row_support

    sec_report = security_report(params, target_bits=target_bits)

    warnings: list[str] = []
    if eps_f >= 0.25:
        warnings.append("evaluated GSW error is high; reduce eta, k, depth, or additions")
    if eta_comp >= 0.25:
        warnings.append("compaction aggregate noise is high; reduce eta_c/B or use a stronger code")
    if params.name.startswith("toy"):
        warnings.append("toy preset: algebraic validation only, not a security parameter set")
    if params.eta == 0 or params.eta_c == 0:
        warnings.append("zero-noise preset: useful for algebra tests but not cryptographic")
    if not sec_report["passes_screen"]:
        warnings.append("attack screening does not meet target; inspect security_screen block")

    return {
        "params": asdict(params),
        "depth": depth,
        "additions": additions,
        "fresh_quality": asdict(fresh),
        "evaluated_quality": asdict(quality),
        "final_error_before_replication": eps_f,
        "compaction_nonzero_terms_B": B,
        "compaction_aggregate_noise": eta_comp,
        "compaction_repetition_failure_bound": comp_fail,
        "per_replica_failure_bound": per_replica_failure,
        "final_replica_failure_bound": final_failure,
        "size_estimates": {
            "input_ciphertext_sparse_entries": input_ct_entries,
            "expansion_key_sparse_entries": expansion_key_entries,
            "compaction_key_field_entries_dense_toy": compaction_key_field_entries,
            "fresh_expanded_sparse_entries": expanded_entries_fresh,
            "final_expanded_sparse_entries_capped": expanded_entries_final,
            "multiplication_cost_proxy": multiplication_cost_proxy,
        },
        "security_screen": sec_report,
        "security_status": "screening estimate only; requires external sparse-LPN/q-ary-LPN cryptanalysis",
        "warnings": warnings,
    }


def format_estimate(est: dict) -> str:
    lines = []
    p = est["params"]
    lines.append(f"Preset: {p['name']}  q={p['q']} n={p['n']} k={p['k']} R={p['replicas']}")
    lines.append(f"Depth: {est['depth']}  additions multiplier: {est['additions']}")
    fq = est["fresh_quality"]
    eq = est["evaluated_quality"]
    lines.append(f"Fresh quality:     w={fq['row_support']} eps={fq['error_probability']:.6g}")
    lines.append(f"Evaluated quality: w={eq['row_support']} eps={eq['error_probability']:.6g}")
    lines.append(f"Compaction B={est['compaction_nonzero_terms_B']} eta_B={est['compaction_aggregate_noise']:.6g}")
    lines.append(f"Per-replica failure bound: {est['per_replica_failure_bound']:.6g}")
    lines.append(f"Final replicated failure bound: {est['final_replica_failure_bound']:.6g}")
    lines.append("Size estimates:")
    for key, value in est["size_estimates"].items():
        lines.append(f"  {key}: {value}")
    sec = est.get("security_screen", {})
    if sec:
        lines.append(f"Security screen min bits: {sec.get('minimum_screen_bits')} passes={sec.get('passes_screen')}")
    if est["warnings"]:
        lines.append("Warnings:")
        for warning in est["warnings"]:
            lines.append(f"  - {warning}")
    lines.append(est["security_status"])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Estimate SABLE-HE toy/prototype parameters")
    parser.add_argument("--preset", default="toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--additions", type=int, default=1)
    parser.add_argument("--target-bits", type=int, default=128)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    est = estimate(PRESETS[args.preset], depth=args.depth, additions=args.additions, target_bits=args.target_bits)
    if args.json:
        print(json.dumps(est, indent=2))
    else:
        print(format_estimate(est))


if __name__ == "__main__":
    main()

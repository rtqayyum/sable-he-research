"""Estimator for SABLE-HE-C2 compaction variants.

This module contains two C2 screens:

1. q-ary plurality C2: a sharper correctness bound for the existing scalar
   CLPN compactor under q-ary symmetric noise.
2. block-dictionary C2: a larger public key that reduces final compaction noise
   terms by grouping secret-key coordinates into small q-ary blocks.

Both are research-screening estimators, not certified cryptanalytic tools.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict
from typing import Any

from .attack import DEFAULT_TARGET_BITS, correctness_eta_ceiling, estimate_attack_surface, expansion_samples, format_attack_summary
from .attacks import security_report
from .codes import qary_plurality_failure_bound
from .estimator import balanced_product_quality, fresh_quality
from .field import majority_failure_bound, qary_piling_up, repetition_failure_bound
from .params import PRESETS, SableParams


def c2_block_widths(N: int, block_size: int) -> list[int]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    return [min(block_size, N - i) for i in range(0, N, block_size)]


def c2_dictionary_entries(q: int, N: int, block_size: int) -> int:
    return sum(q**width - 1 for width in c2_block_widths(N, block_size))


def c2_compaction_terms_worst(N: int, block_size: int, row_support: int) -> int:
    blocks = math.ceil(N / block_size)
    return min(blocks, max(0, min(N, row_support)))


def c2_compaction_terms_randomized(N: int, block_size: int, row_support: int) -> float:
    B = max(0, min(N, row_support))
    if B == 0:
        return 0.0
    widths = c2_block_widths(N, block_size)
    return sum(1.0 - (1.0 - width / N) ** B for width in widths)


def estimate_c2(params: SableParams, depth: int = 1, additions: int = 1, target_bits: int = 128) -> dict[str, Any]:
    """Compatibility estimator for the q-ary plurality C2 decoder."""
    N = params.N
    fresh = fresh_quality(params)
    quality = balanced_product_quality(params, depth)
    eps_f = min(1.0, max(1, additions) * quality.error_probability)
    B = min(N, quality.row_support)
    eta_comp = qary_piling_up(params.q, params.eta_c, B)
    c2_comp_fail = qary_plurality_failure_bound(params.m_c, params.q, eta_comp)
    old_binary_bound = repetition_failure_bound(params.m_c, eta_comp)
    per_replica_failure = min(1.0, eps_f + c2_comp_fail)
    final_failure = majority_failure_bound(params.replicas, per_replica_failure)
    sec_report = security_report(params, target_bits=target_bits)
    warnings: list[str] = []
    if eps_f >= 0.25:
        warnings.append("evaluated GSW error is high; reduce eta, k, depth, or additions")
    if c2_comp_fail > 2.0 ** -40:
        warnings.append("C2 plurality compaction failure is not negligible under this screen")
    if not sec_report.get("passes_screen", False):
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
        "compaction_c2_plurality_failure_bound": c2_comp_fail,
        "compaction_v2_binary_repetition_failure_bound": old_binary_bound,
        "per_replica_failure_bound": per_replica_failure,
        "final_replica_failure_bound": final_failure,
        "size_estimates": {
            "input_ciphertext_sparse_entries": params.replicas * (params.k + 1),
            "expansion_key_sparse_entries": N * N * (params.k + 1),
            "compaction_key_field_entries_dense_toy": N * params.m_c * (params.n_c + 1),
            "c2_public_code_field_entries": params.m_c,
            "fresh_expanded_sparse_entries": params.replicas * N * fresh.row_support,
            "final_expanded_sparse_entries_capped": params.replicas * N * min(N, quality.row_support),
            "multiplication_cost_proxy": N * quality.row_support * quality.row_support,
        },
        "security_screen": sec_report,
        "security_status": "screening estimate only; requires external sparse-LPN/q-ary-LPN cryptanalysis",
        "c2_interpretation": "q-ary plurality improves the correctness bound but does not reduce the number of accumulated CLPN noise terms.",
        "warnings": warnings,
    }


def summarize_params_c2(
    params: SableParams,
    *,
    depth: int = 1,
    additions: int = 1,
    block_size: int | None = None,
    target_bits: float = DEFAULT_TARGET_BITS,
) -> dict[str, Any]:
    """Estimator for the block-dictionary C2 compactor."""
    ell = params.c2_block_size if block_size is None else block_size
    fresh = fresh_quality(params)
    quality = balanced_product_quality(params, depth)
    eps_f = min(1.0, max(1, additions) * quality.error_probability)
    B_v1 = min(params.N, quality.row_support)
    B_c2_worst = c2_compaction_terms_worst(params.N, ell, quality.row_support)
    B_c2_expected = c2_compaction_terms_randomized(params.N, ell, quality.row_support)
    eta_v1 = qary_piling_up(params.q, params.eta_c, B_v1)
    eta_c2 = qary_piling_up(params.q, params.eta_c, B_c2_worst)
    comp_fail_v1 = qary_plurality_failure_bound(params.m_c, params.q, eta_v1)
    comp_fail_c2 = qary_plurality_failure_bound(params.m_c, params.q, eta_c2)
    per_replica_c2 = min(1.0, eps_f + comp_fail_c2)
    final_c2 = majority_failure_bound(params.replicas, per_replica_c2)
    dict_entries = c2_dictionary_entries(params.q, params.N, ell)

    exp_surface = estimate_attack_surface(
        name="expansion_key_sparse_lpn",
        n=params.n,
        q=params.q,
        eta=params.eta,
        samples=expansion_samples(params),
        row_weight=params.k,
        target_bits=target_bits,
    )
    c2_surface = estimate_attack_surface(
        name="c2_block_dictionary_compaction_qary_lpn",
        n=params.n_c,
        q=params.q,
        eta=params.eta_c,
        samples=dict_entries * params.m_c,
        row_weight=None,
        target_bits=target_bits,
    )
    best_bits = min(exp_surface.conservative_min_bits, c2_surface.conservative_min_bits)
    verdict = "research-only"
    if best_bits < target_bits:
        verdict = "reject-parameters"
    elif exp_surface.warnings or c2_surface.warnings:
        verdict = "needs-specialist-review"

    warnings: list[str] = []
    if params.q ** ell > 10000:
        warnings.append("C2 dictionary q^ell is large; reduce q/ell or use estimator-only mode")
    if eta_c2 >= 0.25:
        warnings.append("C2 aggregate compaction noise is high; reduce eta_c, depth, or block count")
    if dict_entries * params.m_c > 10**8:
        warnings.append("C2 public CLPN sample surface is extremely large; attack analysis must account for it")
    if params.name.startswith("toy") or params.name.startswith("c2_toy"):
        warnings.append("toy preset: algebraic validation only, not a security parameter set")
    if params.eta == 0 or params.eta_c == 0:
        warnings.append("zero-noise preset: useful for algebra tests but not cryptographic")

    return {
        "params": asdict(params),
        "depth": depth,
        "additions": additions,
        "c2_block_size": ell,
        "fresh_quality": asdict(fresh),
        "evaluated_quality": asdict(quality),
        "final_error_before_replication": eps_f,
        "v1_coordinate_compaction_terms": B_v1,
        "c2_compaction_terms_worst": B_c2_worst,
        "c2_compaction_terms_random_like_expected": B_c2_expected,
        "v1_compaction_aggregate_noise": eta_v1,
        "c2_compaction_aggregate_noise": eta_c2,
        "v1_compaction_failure_bound": comp_fail_v1,
        "c2_compaction_failure_bound": comp_fail_c2,
        "c2_per_replica_failure_bound": per_replica_c2,
        "c2_final_replica_failure_bound": final_c2,
        "c2_dictionary_entries": dict_entries,
        "c2_public_clpn_samples": dict_entries * params.m_c,
        "size_estimates": {
            "input_ciphertext_sparse_entries": params.replicas * (params.k + 1),
            "expansion_key_sparse_entries": params.N * params.N * (params.k + 1),
            "v1_compaction_key_field_entries_dense_toy": params.N * params.m_c * (params.n_c + 1),
            "c2_dictionary_clpn_ciphertexts": dict_entries,
            "c2_compaction_key_field_entries_dense_toy": dict_entries * params.m_c * (params.n_c + 1),
            "fresh_expanded_sparse_entries": params.replicas * params.N * fresh.row_support,
            "final_expanded_sparse_entries_capped": params.replicas * params.N * min(params.N, quality.row_support),
        },
        "attack_estimates": {
            "target_bits": target_bits,
            "verdict": verdict,
            "surfaces": [exp_surface.to_jsonable(), c2_surface.to_jsonable()],
            "correctness_security_tradeoff": {
                "depth": depth,
                "additions": additions,
                "eta_ceiling_for_eval_error_0p10": correctness_eta_ceiling(params.k, depth, additions),
                "note": "C2 improves compaction-noise accumulation but increases public CLPN samples.",
            },
            "overall_min_attack_bits_proxy": best_bits if math.isfinite(best_bits) else "inf",
        },
        "security_status": "C2 estimates are design-screening proxies, not certified q-ary/sparse-LPN parameters",
        "warnings": warnings,
    }


def format_estimate_c2(est: dict[str, Any]) -> str:
    lines: list[str] = []
    p = est["params"]
    lines.append(f"Preset: {p['name']}  q={p['q']} n={p['n']} k={p['k']} R={p['replicas']}")
    lines.append(f"Depth: {est['depth']}  additions multiplier: {est['additions']}")
    if "c2_block_size" in est:
        lines.append(f"C2 block size: {est['c2_block_size']} dictionary entries: {est['c2_dictionary_entries']}")
        lines.append(
            f"V1 terms={est['v1_coordinate_compaction_terms']} C2 terms={est['c2_compaction_terms_worst']} "
            f"eta_v1={est['v1_compaction_aggregate_noise']:.6g} eta_c2={est['c2_compaction_aggregate_noise']:.6g}"
        )
        lines.append(f"C2 compaction failure: {est['c2_compaction_failure_bound']:.6g}")
        lines.append(f"C2 final replicated failure: {est['c2_final_replica_failure_bound']:.6g}")
    else:
        lines.append(f"Compaction B={est['compaction_nonzero_terms_B']} eta_B={est['compaction_aggregate_noise']:.6g}")
        lines.append(f"C2 q-ary plurality failure: {est['compaction_c2_plurality_failure_bound']:.6g}")
        lines.append(f"Final replicated failure: {est['final_replica_failure_bound']:.6g}")
    lines.append("Size estimates:")
    for key, value in est["size_estimates"].items():
        lines.append(f"  {key}: {value}")
    if est.get("warnings"):
        lines.append("Warnings:")
        for warning in est["warnings"]:
            lines.append(f"  - {warning}")
    if "attack_estimates" in est:
        lines.append("")
        lines.append(format_attack_summary(est["attack_estimates"]))
    elif "security_screen" in est:
        sec = est["security_screen"]
        lines.append(f"Security screen min bits: {sec.get('minimum_screen_bits')} passes={sec.get('passes_screen')}")
    lines.append(est.get("security_status", "screening estimate only"))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Estimate SABLE-HE-C2 parameters")
    parser.add_argument("--preset", default="c2_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--additions", type=int, default=1)
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--target-bits", type=float, default=DEFAULT_TARGET_BITS)
    parser.add_argument("--plurality-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.plurality_only:
        est = estimate_c2(PRESETS[args.preset], depth=args.depth, additions=args.additions, target_bits=int(args.target_bits))
    else:
        est = summarize_params_c2(
            PRESETS[args.preset],
            depth=args.depth,
            additions=args.additions,
            block_size=args.block_size,
            target_bits=args.target_bits,
        )
    print(json.dumps(est, indent=2) if args.json else format_estimate_c2(est))


if __name__ == "__main__":
    main()

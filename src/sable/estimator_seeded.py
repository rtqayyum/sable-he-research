"""Estimator for the seeded C3 block-dictionary compactor."""

from __future__ import annotations

import argparse
import json
import math
from typing import Any

from .estimator_c2 import c2_dictionary_entries, c2_compaction_terms_worst, summarize_params_c2
from .params import PRESETS, SableParams
from .qary_lpn_estimator import estimate_qary_lpn_surface


def seed_field_equivalent_entries(seed_bits: int, q: int) -> float:
    return seed_bits / math.log2(q)


def estimate_seeded_c2(
    params: SableParams,
    *,
    depth: int = 1,
    additions: int = 1,
    block_size: int | None = None,
    target_bits: float = 128.0,
    seed_bits: int = 256,
) -> dict[str, Any]:
    ell = params.c2_block_size if block_size is None else block_size
    base = summarize_params_c2(params, depth=depth, additions=additions, block_size=ell, target_bits=target_bits)
    entries = c2_dictionary_entries(params.q, params.N, ell)
    public_samples = entries * params.m_c
    dense_field_entries = entries * params.m_c * (params.n_c + 1)
    seeded_field_equiv = entries * (params.m_c + seed_field_equivalent_entries(seed_bits, params.q))
    reduction = dense_field_entries / seeded_field_equiv if seeded_field_equiv else math.inf
    terms = c2_compaction_terms_worst(params.N, ell, base['evaluated_quality']['row_support'])

    comp_surface = estimate_qary_lpn_surface(
        name="seeded_c3_block_dictionary_compaction_qary_lpn",
        n=params.n_c,
        q=params.q,
        eta=params.eta_c,
        samples=public_samples,
        row_weight=None,
        target_bits=target_bits,
    )
    exp_surface = estimate_qary_lpn_surface(
        name="sparse_lpn_expansion_key",
        n=params.n,
        q=params.q,
        eta=params.eta,
        samples=params.N * params.N,
        row_weight=params.k,
        target_bits=target_bits,
    )

    warnings: list[str] = []
    warnings.extend(base.get('warnings', []))
    if public_samples > 10**8:
        warnings.append("seeded storage reduces bytes but not the very large public LPN sample surface")
    if entries > 10**6:
        warnings.append("dictionary has more than one million entries; use estimator-only mode or CRT lanes")
    if not comp_surface['passes_target_screen'] or not exp_surface['passes_target_screen']:
        warnings.append("q-ary/sparse-LPN screen does not meet the target; parameters remain research-only")

    return {
        "params": base["params"],
        "depth": depth,
        "additions": additions,
        "c3_seeded_block_size": ell,
        "c3_dictionary_entries": entries,
        "c3_public_clpn_samples": public_samples,
        "c3_compaction_terms_worst": terms,
        "correctness_from_c2_estimator": {
            "c2_compaction_aggregate_noise": base.get("c2_compaction_aggregate_noise"),
            "c2_compaction_failure_bound": base.get("c2_compaction_failure_bound"),
            "c2_final_replica_failure_bound": base.get("c2_final_replica_failure_bound"),
        },
        "storage_estimates": {
            "dense_c2_field_entries": dense_field_entries,
            "seeded_c3_field_entry_equivalent": seeded_field_equiv,
            "seed_bits_per_dictionary_entry": seed_bits,
            "field_entry_storage_reduction_factor": reduction,
            "note": "Seeded storage removes dense A materialization but keeps explicit b vectors and public seeds.",
        },
        "attack_surfaces": {
            "expansion": exp_surface,
            "seeded_dictionary_compaction": comp_surface,
            "note": "Seeded and dense C2 expose the same LPN sample count; seeding changes storage, not attack surface.",
        },
        "base_c2_estimate": base,
        "security_status": "research-only screening; requires external sparse/q-ary-LPN cryptanalysis before any security claim",
        "warnings": warnings,
    }


def format_seeded_estimate(est: dict[str, Any]) -> str:
    p = est['params']
    lines: list[str] = []
    lines.append(f"Preset: {p['name']} q={p['q']} n={p['n']} n_c={p['n_c']} m_c={p['m_c']}")
    lines.append(f"Depth={est['depth']} additions={est['additions']} C3 block size={est['c3_seeded_block_size']}")
    lines.append(f"Dictionary entries: {est['c3_dictionary_entries']}")
    lines.append(f"Public CLPN samples: {est['c3_public_clpn_samples']}")
    lines.append(f"Worst-case compaction terms: {est['c3_compaction_terms_worst']}")
    c = est['correctness_from_c2_estimator']
    lines.append(f"Compaction aggregate noise: {c['c2_compaction_aggregate_noise']:.6g}")
    lines.append(f"Compaction failure bound: {c['c2_compaction_failure_bound']:.6g}")
    lines.append(f"Final replicated failure bound: {c['c2_final_replica_failure_bound']:.6g}")
    s = est['storage_estimates']
    lines.append("Storage model:")
    lines.append(f"  dense C2 field entries: {s['dense_c2_field_entries']}")
    lines.append(f"  seeded C3 field-entry equivalent: {s['seeded_c3_field_entry_equivalent']:.3f}")
    lines.append(f"  storage reduction factor: {s['field_entry_storage_reduction_factor']:.3f}x")
    for name, surface in est['attack_surfaces'].items():
        if name == 'note':
            continue
        bkw = surface['qary_bkw_block_scan']
        lines.append("")
        lines.append(f"Attack surface: {name}")
        lines.append(f"  samples={surface['samples']} ratio={surface['sample_to_dimension_ratio']:.6g} expected_errors={surface['expected_errors']:.6g}")
        lines.append(f"  conservative min bits={surface['conservative_min_bits']} passes={surface['passes_target_screen']}")
        lines.append(f"  q-ary BKW bits={bkw['bits']} block={bkw['block_size']} levels={bkw['levels']} finite={bkw['finite_samples_available']}")
        if surface['warnings']:
            lines.append("  Warnings:")
            for w in surface['warnings']:
                lines.append(f"    - {w}")
    if est['warnings']:
        lines.append("")
        lines.append("Overall warnings:")
        for w in est['warnings']:
            lines.append(f"  - {w}")
    lines.append(est['security_status'])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Estimate seeded C3 block-dictionary compaction")
    parser.add_argument("--preset", default="c2_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--additions", type=int, default=1)
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--seed-bits", type=int, default=256)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    est = estimate_seeded_c2(PRESETS[args.preset], depth=args.depth, additions=args.additions,
                             block_size=args.block_size, target_bits=args.target_bits, seed_bits=args.seed_bits)
    print(json.dumps(est, indent=2) if args.json else format_seeded_estimate(est))


if __name__ == "__main__":
    main()

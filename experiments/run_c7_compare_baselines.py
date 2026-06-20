#!/usr/bin/env python3
"""C7 operation-count/proxy comparison with existing HE families.

This script does not fabricate optimized external wall-clock timings.  It
reports SABLE-C7 operation counts and compaction-surface estimates alongside
which mature HE family is the fair measured baseline for each workload.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.arithmetic import OPERATION_PROFILES
from sable.c7_relation_resistant import estimate_c7_key
from sable.estimator import estimate
from sable.params import PRESETS

BOOLEAN_OPS = {'and', 'or', 'xor', 'not', 'nand', 'nor', 'xnor', 'implies'}


def row_for_operation(params, op_name: str, block_size: int, mode: str) -> dict[str, object]:
    prof = OPERATION_PROFILES[op_name]
    depth = max(1, prof.multiplicative_depth)
    est = estimate(params, depth=depth, additions=max(1, prof.additions + prof.subtractions + prof.public_constants))
    c7 = estimate_c7_key(params, block_size=block_size, mode=mode)  # type: ignore[arg-type]
    best_baseline = 'TFHE/FHEW' if op_name in BOOLEAN_OPS else ('BFV/BGV' if prof.ciphertext_multiplications or prof.linear_ops else 'BFV/BGV')
    return {
        'operation': op_name,
        'inputs': prof.inputs,
        'sable_depth': prof.multiplicative_depth,
        'sable_ct_adds_or_subs': prof.additions + prof.subtractions,
        'sable_public_scalar_muls': prof.scalar_muls,
        'sable_public_constants': prof.public_constants,
        'sable_ct_muls': prof.ciphertext_multiplications,
        'sable_final_row_support_est': est['evaluated_quality']['row_support'],
        'sable_failure_bound_est': est['final_replica_failure_bound'],
        'sable_c7_mode': mode,
        'sable_c7_public_entries': c7['public_entries'],
        'sable_c7_public_clpn_rows': c7['public_clpn_rows'],
        'sable_c7_dense_fallback_terms_bound': c7['dense_fallback_terms_bound'],
        'sable_c7_relation_status': c7['relation_note'],
        'tfhe_fhew_bootstrap_gate_proxy': prof.tfhe_boolean_gate_proxy if op_name in BOOLEAN_OPS else '',
        'bfv_bgv_ciphertext_adds': prof.bfv_bgv_ct_adds,
        'bfv_bgv_ciphertext_muls': prof.bfv_bgv_ct_muls,
        'ckks_applicable': 'approximate-only' if op_name not in BOOLEAN_OPS else 'not preferred for exact Boolean gates',
        'best_external_baseline_family': best_baseline,
        'notes': prof.notes,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c7_standard_toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--ops', default='all')
    parser.add_argument('--block-size', type=int, default=1)
    parser.add_argument('--mode', default='coordinate', choices=['coordinate', 'screened-random'])
    parser.add_argument('--json-output', type=Path, default=None)
    parser.add_argument('--csv-output', type=Path, default=None)
    args = parser.parse_args()
    params = PRESETS[args.preset]
    ops = list(OPERATION_PROFILES) if args.ops == 'all' else [x.strip() for x in args.ops.split(',') if x.strip()]
    rows = [row_for_operation(params, op, args.block_size, args.mode) for op in ops]
    report = {
        'preset': params.name,
        'comparison_type': 'operation-count/proxy table, not optimized external-library timing',
        'c7_mode': args.mode,
        'c7_block_size': args.block_size,
        'baselines': {
            'TFHE/FHEW': 'best-aligned for Boolean gates, comparisons, lookup/PBS-style workloads',
            'BFV/BGV': 'best-aligned for exact modular/integer arithmetic circuits',
            'CKKS': 'best-aligned for approximate real/complex arithmetic; not exact finite-field output',
            'OpenFHE/SEAL/Concrete/TFHE-rs': 'recommended future measured-baseline libraries',
        },
        'rows': rows,
    }
    if args.csv_output:
        with args.csv_output.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    if args.json_output:
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    print(json.dumps(report, indent=2, sort_keys=True, default=str))


if __name__ == '__main__':
    main()

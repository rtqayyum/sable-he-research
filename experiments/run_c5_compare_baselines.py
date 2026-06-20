#!/usr/bin/env python3
"""Compare SABLE operation profiles with existing HE families by workload counts.

This script intentionally reports operation-count/proxy comparisons, not
optimized wall-clock numbers for TFHE/FHEW/BFV/BGV/CKKS.  It is a fair
benchmark-design table: SABLE is a Python research prototype, while the
existing libraries are optimized C++/Rust implementations.
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
from sable.c4_estimator import estimate_c4_key
from sable.c5_surface import estimate_c5_surface
from sable.estimator import estimate
from sable.params import PRESETS


BOOLEAN_OPS = {'and', 'or', 'xor', 'not', 'nand', 'nor', 'xnor', 'implies'}


def row_for_operation(params, op_name: str) -> dict[str, object]:
    prof = OPERATION_PROFILES[op_name]
    depth = max(1, prof.multiplicative_depth)
    est = estimate(params, depth=depth, additions=max(1, prof.additions + prof.subtractions + prof.public_constants))
    c4 = estimate_c4_key(params, block_size=params.c2_block_size, max_terms_per_block=1, mode='projective')
    surface = estimate_c5_surface(params, block_size=params.c2_block_size, relation_trials=100, seed=7)
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
        'sable_c4_public_entries': c4['c4_entries'],
        'sable_c4_public_clpn_rows': c4['c4_public_clpn_rows'],
        'sable_c4_surface_3term_rate_sample': surface.sampled_projective_3term_relation_rate,
        'tfhe_fhew_bootstrap_gate_proxy': prof.tfhe_boolean_gate_proxy if op_name in BOOLEAN_OPS else '',
        'bfv_bgv_ciphertext_adds': prof.bfv_bgv_ct_adds,
        'bfv_bgv_ciphertext_muls': prof.bfv_bgv_ct_muls,
        'ckks_applicable': 'approximate-only' if op_name not in BOOLEAN_OPS else 'not preferred for Boolean exactness',
        'notes': prof.notes,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c4_projective_toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--ops', default='all')
    parser.add_argument('--json-output', type=Path, default=None)
    parser.add_argument('--csv-output', type=Path, default=None)
    args = parser.parse_args()
    params = PRESETS[args.preset]
    ops = list(OPERATION_PROFILES) if args.ops == 'all' else [x.strip() for x in args.ops.split(',') if x.strip()]
    rows = [row_for_operation(params, op) for op in ops]
    report = {
        'preset': params.name,
        'comparison_type': 'operation-count/proxy table, not measured optimized-library timing',
        'baselines': {
            'TFHE/FHEW': 'best-aligned for Boolean gates and programmable bootstrapping/table lookup workloads',
            'BFV/BGV': 'best-aligned for exact modular/integer arithmetic circuits',
            'CKKS': 'best-aligned for approximate real/complex arithmetic, not exact finite-field outputs',
            'OpenFHE/SEAL/Concrete': 'recommended libraries for future measured baselines',
        },
        'rows': rows,
    }
    if args.csv_output:
        with args.csv_output.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    if args.json_output:
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

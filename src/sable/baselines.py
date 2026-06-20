
"""Baseline-comparison scaffolding for SABLE-HE experiments.

This module does not claim measured TFHE/BFV/BGV/CKKS timings.  It produces
workload descriptors and operation-count proxies so that future experiments
can be run fairly against concrete libraries such as OpenFHE or TFHE-rs.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

from .estimator import estimate
from .params import PRESETS, SableParams


@dataclass(frozen=True)
class Workload:
    name: str
    field: str
    inputs: int
    multiplicative_depth: int
    additions: int
    multiplications: int
    boolean_gates: int
    notes: str


def balanced_product_workload(depth: int) -> Workload:
    inputs = 2 ** depth
    multiplications = max(0, inputs - 1)
    return Workload(
        name=f'balanced_product_depth_{depth}',
        field='F_q arithmetic',
        inputs=inputs,
        multiplicative_depth=depth,
        additions=0,
        multiplications=multiplications,
        boolean_gates=multiplications,
        notes='Product tree; Boolean AND when inputs are encoded as 0/1.',
    )


def quadratic_form_workload(terms: int) -> Workload:
    return Workload(
        name=f'quadratic_form_{terms}_terms',
        field='F_q arithmetic',
        inputs=2 * terms,
        multiplicative_depth=1,
        additions=max(0, terms - 1),
        multiplications=terms,
        boolean_gates=terms + max(0, terms - 1),
        notes='Sum of pairwise products; first realistic SABLE-HE target.',
    )


def model_comparison(params: SableParams, workload: Workload) -> dict:
    est = estimate(params, depth=workload.multiplicative_depth, additions=max(1, workload.additions + 1))
    sable = {
        'input_ciphertext_sparse_entries': est['size_estimates']['input_ciphertext_sparse_entries'],
        'expansion_key_sparse_entries': est['size_estimates']['expansion_key_sparse_entries'],
        'final_expanded_sparse_entries_capped': est['size_estimates']['final_expanded_sparse_entries_capped'],
        'multiplication_cost_proxy': est['size_estimates']['multiplication_cost_proxy'] * max(1, workload.multiplications),
        'per_replica_failure_bound': est['per_replica_failure_bound'],
        'final_replica_failure_bound': est['final_replica_failure_bound'],
    }
    baselines = {
        'TFHE_FHEW_boolean_proxy': {
            'programmable_bootstrap_or_gate_proxy': workload.boolean_gates,
            'comment': 'Boolean-circuit baseline: measure actual bootstrapping/gate time in OpenFHE/TFHE-rs later.',
        },
        'BFV_BGV_exact_arithmetic_proxy': {
            'ciphertext_multiplications': workload.multiplications,
            'ciphertext_additions': workload.additions,
            'multiplicative_depth': workload.multiplicative_depth,
            'comment': 'Exact-arithmetic baseline: measure with OpenFHE BFV/BGV at comparable plaintext modulus.',
        },
        'CKKS_approximate_proxy': {
            'ciphertext_multiplications': workload.multiplications,
            'ciphertext_additions': workload.additions,
            'comment': 'Only relevant for approximate real workloads, not finite-field correctness.',
        },
    }
    return {
        'params': params.name,
        'workload': asdict(workload),
        'sable_proxy': sable,
        'baseline_proxies': baselines,
        'warning': 'Proxy model only; not a measured benchmark.',
    }


def default_workloads() -> list[Workload]:
    return [
        balanced_product_workload(1),
        balanced_product_workload(2),
        quadratic_form_workload(4),
        quadratic_form_workload(16),
    ]


def flatten_for_csv(row: dict) -> dict[str, object]:
    workload = row['workload']
    sable = row['sable_proxy']
    return {
        'params': row['params'],
        'workload': workload['name'],
        'inputs': workload['inputs'],
        'depth': workload['multiplicative_depth'],
        'additions': workload['additions'],
        'multiplications': workload['multiplications'],
        'boolean_gate_proxy': workload['boolean_gates'],
        'sable_input_sparse_entries': sable['input_ciphertext_sparse_entries'],
        'sable_expansion_key_sparse_entries': sable['expansion_key_sparse_entries'],
        'sable_final_expanded_sparse_entries_capped': sable['final_expanded_sparse_entries_capped'],
        'sable_multiplication_cost_proxy': sable['multiplication_cost_proxy'],
        'sable_per_replica_failure_bound': sable['per_replica_failure_bound'],
        'sable_final_failure_bound': sable['final_replica_failure_bound'],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate SABLE-HE baseline-comparison proxy tables')
    parser.add_argument('--preset', default='toy_depth2', choices=sorted(PRESETS))
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--csv-out', type=Path, default=None)
    args = parser.parse_args()
    rows = [model_comparison(PRESETS[args.preset], workload) for workload in default_workloads()]
    if args.csv_out:
        flat = [flatten_for_csv(row) for row in rows]
        with args.csv_out.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(flat[0]))
            writer.writeheader()
            writer.writerows(flat)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            flat = flatten_for_csv(row)
            print(
                f"{flat['params']} {flat['workload']}: depth={flat['depth']} "
                f"mul={flat['multiplications']} SABLE-mul-proxy={flat['sable_multiplication_cost_proxy']} "
                f"TFHE-gate-proxy={flat['boolean_gate_proxy']} fail={flat['sable_final_failure_bound']:.3g}"
            )


if __name__ == '__main__':
    main()

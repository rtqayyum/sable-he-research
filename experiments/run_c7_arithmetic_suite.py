#!/usr/bin/env python3
"""Run the full arithmetic suite with the C7 relation-resistant compactor."""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from experiments.run_c5_arithmetic_suite import build_operation
from sable import arithmetic as A
from sable.c7_relation_resistant import compaction_term_count
from sable.params import PRESETS
from sable.sable import compact_c7, decrypt_relation_resistant_c7, keygen_relation_resistant_c7


def decrypt_ct(kp, ct):
    compacted = compact_c7(kp, ct)
    return decrypt_relation_resistant_c7(kp, compacted), compacted


def run_op(kp, op: str, trials: int, seed: int):
    rng = random.Random(seed + sum(ord(c) for c in op) * 1009)
    rows = []
    for i in range(trials):
        t0 = time.perf_counter()
        ct, expected, values = build_operation(kp, op, rng, seed_base=20_000_000 + 10_000 * i + len(op))
        t_eval = time.perf_counter()
        got, compacted = decrypt_ct(kp, ct)
        t_dec = time.perf_counter()
        term_counts = [compaction_term_count(C.last_row(), kp.compaction_basis_c7) for C in ct]
        rows.append({
            'operation': op,
            'trial': i,
            'ok': got == expected,
            'expected': expected,
            'got': got,
            'build_eval_time_s': t_eval - t0,
            'compact_decrypt_time_s': t_dec - t_eval,
            'total_time_s': t_dec - t0,
            'max_row_support': max(C.max_row_support() for C in ct),
            'total_output_nnz': sum(C.total_nnz() for C in ct),
            'max_c7_compaction_terms': max(term_counts),
            'mean_c7_compaction_terms': statistics.mean(term_counts),
            'values': values,
        })
    return rows


def summarize(rows):
    def stat(key):
        vals = [float(r[key]) for r in rows]
        return {'mean': statistics.mean(vals), 'median': statistics.median(vals), 'min': min(vals), 'max': max(vals)}
    return {
        'trials': len(rows),
        'successes': sum(1 for r in rows if r['ok']),
        'failures': sum(1 for r in rows if not r['ok']),
        'build_eval_time_s': stat('build_eval_time_s'),
        'compact_decrypt_time_s': stat('compact_decrypt_time_s'),
        'total_time_s': stat('total_time_s'),
        'max_row_support_seen': max(r['max_row_support'] for r in rows),
        'max_total_output_nnz_seen': max(r['total_output_nnz'] for r in rows),
        'max_c7_compaction_terms_seen': max(r['max_c7_compaction_terms'] for r in rows),
        'mean_c7_compaction_terms': stat('mean_c7_compaction_terms'),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c4_projective_toy_clean', choices=sorted(PRESETS))
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--seed', type=int, default=2027)
    parser.add_argument('--ops', default='all', help='comma-separated operation names or all')
    parser.add_argument('--block-size', type=int, default=1)
    parser.add_argument('--mode', default='coordinate', choices=['coordinate', 'screened-random'])
    parser.add_argument('--entries-per-block', type=int, default=None)
    parser.add_argument('--json-output', type=Path, default=None)
    parser.add_argument('--csv-output', type=Path, default=None)
    args = parser.parse_args()
    ops = list(A.OPERATION_PROFILES) if args.ops == 'all' else [x.strip() for x in args.ops.split(',') if x.strip()]
    params = PRESETS[args.preset]
    t0 = time.perf_counter()
    kp = keygen_relation_resistant_c7(
        params,
        seed=args.seed,
        block_size=args.block_size,
        mode=args.mode,
        entries_per_block=args.entries_per_block,
    )
    keygen_time = time.perf_counter() - t0
    rows = []
    for op in ops:
        rows.extend(run_op(kp, op, args.trials, args.seed))
    by_op = {op: summarize([r for r in rows if r['operation'] == op]) for op in ops}
    report = {
        'preset': args.preset,
        'c7_mode': args.mode,
        'c7_block_size': args.block_size,
        'keygen_time_s': keygen_time,
        'operations': ops,
        'summary_by_operation': by_op,
        'note': 'Pure-Python validation prototype. Do not compare wall-clock directly against optimized FHE libraries.',
    }
    if args.csv_output:
        with args.csv_output.open('w', newline='') as f:
            fieldnames = ['operation','trial','ok','expected','got','build_eval_time_s','compact_decrypt_time_s','total_time_s','max_row_support','total_output_nnz','max_c7_compaction_terms','mean_c7_compaction_terms']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row[k] for k in fieldnames})
    if args.json_output:
        args.json_output.write_text(json.dumps({'report': report, 'rows': rows}, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

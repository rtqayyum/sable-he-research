#!/usr/bin/env python3
"""Run correctness and timing checks for SABLE-HE arithmetic operations.

The script uses the C4 projective compactor by default.  It tests the
low-degree arithmetic interface over F_q and the Boolean gates obtained by
encoding bits as 0/1 in F_q.  Timings are for the pure-Python validation
prototype and are not comparable to optimized C/C++ FHE libraries.
"""

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

from sable import arithmetic as A
from sable.params import PRESETS
from sable.sable import compact_basis_c4, decrypt_basis_c4, encrypt, expand, keygen_basis_c4


def enc(kp, value: int, seed: int):
    return expand(kp, encrypt(kp, value % kp.params.q, seed=seed))


def decrypt_ct(kp, ct):
    return decrypt_basis_c4(kp, compact_basis_c4(kp, ct))


def build_operation(kp, op: str, rng: random.Random, seed_base: int):
    q = kp.params.q
    if op == 'add':
        x, y = rng.randrange(q), rng.randrange(q)
        return A.add(enc(kp, x, seed_base+1), enc(kp, y, seed_base+2)), (x + y) % q, {'x': x, 'y': y}
    if op == 'sub':
        x, y = rng.randrange(q), rng.randrange(q)
        return A.sub(enc(kp, x, seed_base+1), enc(kp, y, seed_base+2)), (x - y) % q, {'x': x, 'y': y}
    if op == 'neg':
        x = rng.randrange(q)
        return A.neg(enc(kp, x, seed_base+1)), (-x) % q, {'x': x}
    if op == 'scalar_mul':
        x, a = rng.randrange(q), rng.randrange(1, q)
        return A.scalar_mul(enc(kp, x, seed_base+1), a), (a * x) % q, {'x': x, 'a': a}
    if op == 'add_const':
        x, c = rng.randrange(q), rng.randrange(q)
        return A.add_const(enc(kp, x, seed_base+1), c), (x + c) % q, {'x': x, 'c': c}
    if op == 'mul':
        x, y = rng.randrange(q), rng.randrange(q)
        return A.mul(enc(kp, x, seed_base+1), enc(kp, y, seed_base+2)), (x * y) % q, {'x': x, 'y': y}
    if op == 'square':
        x = rng.randrange(q)
        return A.square(enc(kp, x, seed_base+1)), (x * x) % q, {'x': x}
    if op == 'affine':
        x, y = rng.randrange(q), rng.randrange(q)
        return A.affine_combination([(3, enc(kp, x, seed_base+1)), (2, enc(kp, y, seed_base+2))], constant=5), (3*x + 2*y + 5) % q, {'x': x, 'y': y}
    if op == 'dot4':
        xs = [rng.randrange(q) for _ in range(4)]
        coeffs = [1, 2, 3, 4]
        cts = [enc(kp, x, seed_base + i + 1) for i, x in enumerate(xs)]
        return A.dot_public(coeffs, cts, constant=6), (sum(a*x for a, x in zip(coeffs, xs)) + 6) % q, {'xs': xs}
    if op == 'poly2':
        x = rng.randrange(q)
        # p(x)=3+2x+5x^2
        return A.poly_eval(enc(kp, x, seed_base+1), [3, 2, 5]), (3 + 2*x + 5*x*x) % q, {'x': x}
    if op == 'product4':
        xs = [rng.randrange(q) for _ in range(4)]
        cts = [enc(kp, x, seed_base + i + 1) for i, x in enumerate(xs)]
        expected = 1
        for x in xs:
            expected = (expected * x) % q
        return A.balanced_product(cts), expected, {'xs': xs}
    if op == 'quadratic_form':
        xs = [rng.randrange(q) for _ in range(4)]
        cts = [enc(kp, x, seed_base + i + 1) for i, x in enumerate(xs)]
        out = A.add_const(A.add(A.mul(cts[0], cts[1]), A.mul(cts[2], cts[3])), 5)
        return out, (xs[0]*xs[1] + xs[2]*xs[3] + 5) % q, {'xs': xs}

    # Boolean gates use bit inputs.
    if op in {'and', 'or', 'xor', 'nand', 'nor', 'xnor', 'implies'}:
        x, y = rng.randrange(2), rng.randrange(2)
        X, Y = enc(kp, x, seed_base+1), enc(kp, y, seed_base+2)
        funcs = {
            'and': A.gate_and,
            'or': A.gate_or,
            'xor': A.gate_xor,
            'nand': A.gate_nand,
            'nor': A.gate_nor,
            'xnor': A.gate_xnor,
            'implies': A.gate_implies,
        }
        expected = {
            'and': x & y,
            'or': x | y,
            'xor': x ^ y,
            'nand': 1 - (x & y),
            'nor': 1 - (x | y),
            'xnor': 1 - (x ^ y),
            'implies': int((not x) or bool(y)),
        }[op]
        return funcs[op](X, Y), expected, {'x': x, 'y': y}
    if op == 'not':
        x = rng.randrange(2)
        return A.gate_not(enc(kp, x, seed_base+1)), 1 - x, {'x': x}
    raise ValueError(f'unsupported operation: {op}')


def run_op(kp, op: str, trials: int, seed: int):
    rng = random.Random(seed + hash(op) % 1_000_000)
    rows = []
    for i in range(trials):
        t0 = time.perf_counter()
        ct, expected, values = build_operation(kp, op, rng, seed_base=10_000_000 + 10_000 * i + len(op))
        t_eval = time.perf_counter()
        got = decrypt_ct(kp, ct)
        t_dec = time.perf_counter()
        max_support = max(C.max_row_support() for C in ct)
        total_nnz = sum(C.total_nnz() for C in ct)
        rows.append({
            'operation': op,
            'trial': i,
            'ok': got == expected,
            'expected': expected,
            'got': got,
            'build_eval_time_s': t_eval - t0,
            'compact_decrypt_time_s': t_dec - t_eval,
            'total_time_s': t_dec - t0,
            'max_row_support': max_support,
            'total_output_nnz': total_nnz,
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
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c4_projective_toy_clean', choices=sorted(PRESETS))
    parser.add_argument('--trials', type=int, default=5)
    parser.add_argument('--seed', type=int, default=2026)
    parser.add_argument('--ops', default='all', help='comma-separated operation names or all')
    parser.add_argument('--json-output', type=Path, default=None)
    parser.add_argument('--csv-output', type=Path, default=None)
    args = parser.parse_args()
    if args.ops == 'all':
        ops = list(A.OPERATION_PROFILES)
    else:
        ops = [x.strip() for x in args.ops.split(',') if x.strip()]
    params = PRESETS[args.preset]
    t0 = time.perf_counter()
    kp = keygen_basis_c4(params, seed=args.seed, block_size=params.c2_block_size, max_terms_per_block=1, mode='projective')
    keygen_time = time.perf_counter() - t0
    rows = []
    for op in ops:
        rows.extend(run_op(kp, op, args.trials, args.seed))
    by_op = {op: summarize([r for r in rows if r['operation'] == op]) for op in ops}
    profiles = {name: profile.__dict__ for name, profile in A.OPERATION_PROFILES.items() if name in ops}
    report = {
        'preset': args.preset,
        'keygen_time_s': keygen_time,
        'operations': ops,
        'profiles': profiles,
        'summary_by_operation': by_op,
        'note': 'Pure-Python validation prototype. Do not compare wall-clock directly against optimized FHE libraries.',
    }
    if args.csv_output:
        with args.csv_output.open('w', newline='') as f:
            fieldnames = ['operation', 'trial', 'ok', 'expected', 'got', 'build_eval_time_s', 'compact_decrypt_time_s', 'total_time_s', 'max_row_support', 'total_output_nnz']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row[k] for k in fieldnames})
    if args.json_output:
        args.json_output.write_text(json.dumps({'report': report, 'rows': rows}, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Benchmark SABLE-HE toy Boolean/arithmetic gates.

This benchmark measures the Python validation prototype only. It is not a
production implementation benchmark and should not be compared directly with
optimized C/C++ TFHE/BFV/BGV libraries. Its purpose is to expose the growth
bottlenecks in SABLE-HE: expansion-key use, sparse matrix multiplication,
compaction, and final decoding.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.params import PRESETS
from sable.sable import compact, decrypt, encrypt, eval_add, eval_mul, expand, keygen


def encrypt_expand(kp, value: int, seed: int):
    c = encrypt(kp, value, seed=seed)
    return expand(kp, c)


def gate_eval(kp, gate: str, rng: random.Random, seed_base: int):
    q = kp.params.q
    values = {}
    t0 = time.perf_counter()

    if gate in {'and', 'or', 'xor', 'mul'}:
        x = rng.randrange(2 if gate in {'and', 'or', 'xor'} else q)
        y = rng.randrange(2 if gate in {'and', 'or', 'xor'} else q)
        cx = encrypt_expand(kp, x, seed_base + 1)
        cy = encrypt_expand(kp, y, seed_base + 2)
        t_inputs = time.perf_counter()
        xy = eval_mul(cx, cy)
        if gate in {'and', 'mul'}:
            out = xy
            expected = (x * y) % q
        elif gate == 'or':
            x_plus_y = eval_add(cx, cy)
            out = eval_add(x_plus_y, [C.scale(q - 1) for C in xy])
            expected = int(bool(x or y))
        else:
            x_plus_y = eval_add(cx, cy)
            out = eval_add(x_plus_y, [C.scale(q - 2) for C in xy])
            expected = x ^ y
        t_eval = time.perf_counter()
        compacted = compact(kp, out)
        got = decrypt(kp, compacted)
        t_dec = time.perf_counter()
        values.update({'x': x, 'y': y})
    elif gate == 'quad_sum':
        xs = [rng.randrange(q) for _ in range(4)]
        c = [encrypt_expand(kp, x, seed_base + i + 1) for i, x in enumerate(xs)]
        t_inputs = time.perf_counter()
        out = eval_add(eval_mul(c[0], c[1]), eval_mul(c[2], c[3]))
        expected = (xs[0] * xs[1] + xs[2] * xs[3]) % q
        t_eval = time.perf_counter()
        compacted = compact(kp, out)
        got = decrypt(kp, compacted)
        t_dec = time.perf_counter()
        values.update({f'x{i+1}': x for i, x in enumerate(xs)})
    else:
        raise ValueError(f'unknown gate: {gate}')

    max_support = max(C.max_row_support() for C in out)
    total_nnz = sum(C.total_nnz() for C in out)
    return {
        'ok': got == expected,
        'expected': expected,
        'got': got,
        'input_time_s': t_inputs - t0,
        'eval_time_s': t_eval - t_inputs,
        'compact_decrypt_time_s': t_dec - t_eval,
        'total_time_s': t_dec - t0,
        'max_row_support': max_support,
        'total_output_nnz': total_nnz,
        'values': values,
    }


def summarize(rows: list[dict]) -> dict:
    def stats(key: str) -> dict:
        vals = [float(r[key]) for r in rows]
        return {
            'mean': statistics.mean(vals),
            'median': statistics.median(vals),
            'min': min(vals),
            'max': max(vals),
        }
    return {
        'trials': len(rows),
        'successes': sum(1 for r in rows if r['ok']),
        'failures': sum(1 for r in rows if not r['ok']),
        'input_time_s': stats('input_time_s'),
        'eval_time_s': stats('eval_time_s'),
        'compact_decrypt_time_s': stats('compact_decrypt_time_s'),
        'total_time_s': stats('total_time_s'),
        'max_row_support_seen': max(r['max_row_support'] for r in rows) if rows else 0,
        'max_total_output_nnz_seen': max(r['total_output_nnz'] for r in rows) if rows else 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--gate', default='and', choices=['and', 'or', 'xor', 'mul', 'quad_sum'])
    parser.add_argument('--trials', type=int, default=20)
    parser.add_argument('--seed', type=int, default=123)
    parser.add_argument('--json-output')
    parser.add_argument('--csv-output')
    args = parser.parse_args()

    params = PRESETS[args.preset]
    rng = random.Random(args.seed + 1009)
    tracemalloc.start()
    t_keygen0 = time.perf_counter()
    kp = keygen(params, seed=args.seed)
    keygen_time = time.perf_counter() - t_keygen0

    rows = []
    for trial in range(args.trials):
        row = gate_eval(kp, args.gate, rng, seed_base=10_000_000 + 100 * trial)
        row.update({'trial': trial, 'preset': args.preset, 'gate': args.gate})
        rows.append(row)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    summary = {
        'preset': args.preset,
        'gate': args.gate,
        'keygen_time_s': keygen_time,
        'tracemalloc_current_bytes': current,
        'tracemalloc_peak_bytes': peak,
        'summary': summarize(rows),
        'note': 'Python validation prototype timing only; not an optimized cryptographic library benchmark.',
        'first_failures': [r for r in rows if not r['ok']][:5],
    }

    if args.csv_output:
        with open(args.csv_output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'trial', 'preset', 'gate', 'ok', 'expected', 'got',
                'input_time_s', 'eval_time_s', 'compact_decrypt_time_s',
                'total_time_s', 'max_row_support', 'total_output_nnz',
            ])
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r[k] for k in writer.fieldnames})
    if args.json_output:
        Path(args.json_output).write_text(json.dumps({'summary': summary, 'rows': rows}, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()

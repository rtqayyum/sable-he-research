"""C5 public-surface diagnostics for C4 projective compaction.

These routines are screening tools, not cryptanalytic proofs. They quantify
how much public CLPN material C4 exposes, how it compares with the legacy
coordinate compactor and the C2/C3 full block dictionary, and how many
low-weight projective relations are expected from publishing one line from
each one-dimensional subspace of F_q^b.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import asdict, dataclass

from .additive_basis import find_low_weight_relation, projective_count, projective_representatives
from .params import PRESETS, SableParams


@dataclass(frozen=True)
class C5SurfaceReport:
    params: str
    q: int
    N: int
    block_size: int
    num_blocks: int
    legacy_entries: int
    c2_entries: int
    c4_projective_entries: int
    c4_vs_c2_ratio: float
    c4_public_clpn_rows: int
    c4_public_dense_field_elements: int
    expansion_key_sparse_rows: int
    expansion_key_sparse_entries_rough: int
    projective_entries_per_full_block: int
    low_weight_2_relation_found: bool
    low_weight_3_relation_found: bool
    sampled_projective_3term_relation_rate: float
    log2_public_clpn_rows: float
    warning: str


def _widths(N: int, block_size: int) -> list[int]:
    return [min(block_size, N - start) for start in range(0, N, block_size)]


def _sample_projective_3term_rate(q: int, width: int, trials: int, seed: int) -> float:
    if width < 2 or trials <= 0:
        return 0.0
    rng = random.Random(seed)
    reps = projective_representatives(q, width)
    rep_set = set(reps)
    hits = 0
    total = 0
    for _ in range(trials):
        u = rng.choice(reps)
        v = rng.choice(reps)
        # Skip same line.  Reps are already projectively unique.
        if u == v:
            continue
        a = rng.randrange(1, q)
        b = rng.randrange(1, q)
        w = tuple((a * u[i] + b * v[i]) % q for i in range(width))
        if all(x == 0 for x in w):
            continue
        # Normalize w to the projective representative convention: first nonzero is 1.
        first = next(i for i, x in enumerate(w) if x % q)
        inv = pow(w[first], -1, q)
        wrep = tuple((inv * x) % q for x in w)
        total += 1
        if wrep in rep_set:
            hits += 1
    return hits / max(1, total)


def estimate_c5_surface(params: SableParams, *, block_size: int | None = None, relation_trials: int = 1000, seed: int = 123) -> C5SurfaceReport:
    q = params.q
    N = params.N
    ell = params.c2_block_size if block_size is None else block_size
    widths = _widths(N, ell)
    c2_entries = sum(q**w - 1 for w in widths)
    c4_entries = sum(projective_count(q, w) for w in widths)
    full_width = max(widths)
    reps = projective_representatives(q, full_width)
    # Exhaustive relation search is only safe for small blocks.
    two_rel = bool(find_low_weight_relation(q, reps, 2, limit=1)) if len(reps) <= 500 else False
    three_rel = bool(find_low_weight_relation(q, reps, 3, limit=1)) if len(reps) <= 250 else full_width >= 2
    rate3 = _sample_projective_3term_rate(q, full_width, relation_trials, seed)
    public_rows = c4_entries * params.m_c
    warning = (
        'C4 reduces the number of public CLPN entries versus C2/C3, but projective closure intentionally '
        'contains many weight-3 linear relations when block width is at least 2. Treat this as a public-sample '
        'surface requiring dedicated q-ary-LPN analysis, not as a security proof.'
    )
    return C5SurfaceReport(
        params=params.name,
        q=q,
        N=N,
        block_size=ell,
        num_blocks=len(widths),
        legacy_entries=N,
        c2_entries=c2_entries,
        c4_projective_entries=c4_entries,
        c4_vs_c2_ratio=(c4_entries / c2_entries) if c2_entries else 0.0,
        c4_public_clpn_rows=public_rows,
        c4_public_dense_field_elements=public_rows * (params.n_c + 1),
        expansion_key_sparse_rows=N * N,
        expansion_key_sparse_entries_rough=N * N * (params.k + 1),
        projective_entries_per_full_block=projective_count(q, full_width),
        low_weight_2_relation_found=two_rel,
        low_weight_3_relation_found=three_rel,
        sampled_projective_3term_relation_rate=rate3,
        log2_public_clpn_rows=math.log2(public_rows) if public_rows > 0 else float('-inf'),
        warning=warning,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description='C5 public-surface diagnostic for C4 projective compaction')
    parser.add_argument('--preset', default='c4_projective_toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--block-size', type=int, default=None)
    parser.add_argument('--relation-trials', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=123)
    args = parser.parse_args()
    report = estimate_c5_surface(PRESETS[args.preset], block_size=args.block_size, relation_trials=args.relation_trials, seed=args.seed)
    print(json.dumps(asdict(report), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

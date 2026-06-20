"""C4 sparse additive-basis estimator."""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass

from .additive_basis import coverage_capacity, log_q_sparse_volume, projective_count, projective_representatives, random_basis
from .clpn_c4_basis import estimate_c4_key, screen_basis
from .params import SableParams


@dataclass(frozen=True)
class C4Comparison:
    name: str
    q: int
    N: int
    block_size: int
    num_blocks: int
    v1_entries: int
    c2_entries: int
    c3_seeded_entries: int
    c4_entries: int
    c4_vs_c2_ratio: float
    c4_public_clpn_rows: int
    terms_v1_dense: int
    terms_c2: int
    terms_c4_bound: int
    eta_c4_bound: float
    repetition_failure_bound_c4: float
    capacity_ratio_full_block: float
    log_q_volume_full_block: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def compare(params: SableParams, *, block_size: int | None = None, max_terms_per_block: int = 1, mode: str = "projective", entries_per_full_block: int | None = None) -> C4Comparison:
    ell = params.c2_block_size if block_size is None else block_size
    est = estimate_c4_key(
        params,
        block_size=ell,
        max_terms_per_block=max_terms_per_block,
        mode=mode,  # type: ignore[arg-type]
        entries_per_full_block=entries_per_full_block,
    )
    full_width = min(ell, params.N)
    if mode == "projective":
        entries_full = projective_count(params.q, full_width)
    else:
        if entries_per_full_block is None:
            raise ValueError("entries_per_full_block required for random mode")
        entries_full = entries_per_full_block
    return C4Comparison(
        name=params.name,
        q=params.q,
        N=params.N,
        block_size=ell,
        num_blocks=int(est["num_blocks"]),
        v1_entries=int(est["legacy_entries"]),
        c2_entries=int(est["c2_entries"]),
        c3_seeded_entries=int(est["c2_entries"]),
        c4_entries=int(est["c4_entries"]),
        c4_vs_c2_ratio=float(est["c4_vs_c2_entry_ratio"]),
        c4_public_clpn_rows=int(est["c4_public_clpn_rows"]),
        terms_v1_dense=int(est["v1_terms_dense_blocks"]),
        terms_c2=int(est["c2_terms"]),
        terms_c4_bound=int(est["c4_terms_bound"]),
        eta_c4_bound=float(est["eta_c4_bound"]),
        repetition_failure_bound_c4=float(est["repetition_failure_bound_c4"]),
        capacity_ratio_full_block=coverage_capacity(params.q, full_width, entries_full, max_terms_per_block),
        log_q_volume_full_block=log_q_sparse_volume(params.q, entries_full, max_terms_per_block),
    )


def screen_projective(params: SableParams, *, block_size: int | None = None, relation_weight: int = 3) -> dict[str, float | int | str]:
    ell = params.c2_block_size if block_size is None else block_size
    width = min(ell, params.N)
    basis = projective_representatives(params.q, width)
    return screen_basis(params.q, width, basis, 1, random.Random(1337), samples=min(200, params.q**width), relation_weight=relation_weight)


def screen_random(params: SableParams, *, block_size: int | None = None, entries: int = 32, terms: int = 3, samples: int = 200, seed: int = 1337) -> dict[str, float | int | str]:
    ell = params.c2_block_size if block_size is None else block_size
    width = min(ell, params.N)
    rng = random.Random(seed)
    basis = random_basis(params.q, width, entries, rng, include_standard=True)
    return screen_basis(params.q, width, basis, terms, rng, samples=samples, relation_weight=3)

"""C4 sparse additive-basis compaction layer.

C4 stores CLPN encryptions of <u_j, s_B> for a codebook of public masks u_j.
The default projective codebook stores one representative per 1-dimensional
subspace of F_q^b.  Since CLPN is linearly homomorphic, scalar multiples are
handled by ciphertext scaling, so projective C4 keeps one CLPN term per active
block while reducing public entries by a factor close to q compared with C2.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Literal, Sequence

from . import clpn
from .additive_basis import (
    coverage_capacity,
    decompose_sparse,
    estimate_sample_coverage,
    find_low_weight_relation,
    log_q_sparse_volume,
    projective_count,
    projective_representatives,
    random_basis,
)
from .field import dot_dense, qary_piling_up, repetition_failure_bound
from .params import SableParams
from .sparse import SparseVector

BasisMode = Literal["projective", "random"]


@dataclass(frozen=True)
class C4BasisKey:
    q: int
    N: int
    block_size: int
    n_c: int
    m_c: int
    max_terms_per_block: int
    basis_mode: str
    bases: list[list[tuple[int, ...]]]
    blocks: list[list[clpn.CLPNCiphertext]]

    def __post_init__(self) -> None:
        if self.N <= 0:
            raise ValueError("N must be positive")
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")
        if self.max_terms_per_block <= 0:
            raise ValueError("max_terms_per_block must be positive")
        expected_blocks = math.ceil(self.N / self.block_size)
        if len(self.bases) != expected_blocks or len(self.blocks) != expected_blocks:
            raise ValueError("incorrect number of C4 blocks")
        for block_index, (basis, cts) in enumerate(zip(self.bases, self.blocks)):
            width = self.block_width(block_index)
            if len(basis) != len(cts):
                raise ValueError("basis/ciphertext count mismatch")
            if not basis:
                raise ValueError("basis cannot be empty")
            for vec, ct in zip(basis, cts):
                if len(vec) != width:
                    raise ValueError("basis vector has wrong width")
                if all((x % self.q) == 0 for x in vec):
                    raise ValueError("zero basis vector is not stored")
                if ct.q != self.q or ct.n != self.n_c or ct.m != self.m_c:
                    raise ValueError("CLPN ciphertext incompatible with C4 key")

    @property
    def num_blocks(self) -> int:
        return len(self.bases)

    @property
    def public_entries(self) -> int:
        return sum(len(block) for block in self.blocks)

    @property
    def public_clpn_rows(self) -> int:
        return self.public_entries * self.m_c

    @property
    def public_field_elements_dense(self) -> int:
        return self.public_entries * self.m_c * (self.n_c + 1)

    def block_width(self, block_index: int) -> int:
        start = block_index * self.block_size
        return max(0, min(self.block_size, self.N - start))


def _secret_blocks(tilde_s: list[int], block_size: int) -> list[list[int]]:
    return [tilde_s[start : start + block_size] for start in range(0, len(tilde_s), block_size)]


def _basis_for_width(q: int, width: int, rng: random.Random, *, mode: BasisMode, basis_size: int | None) -> list[tuple[int, ...]]:
    if mode == "projective":
        return projective_representatives(q, width)
    if mode == "random":
        if basis_size is None:
            raise ValueError("basis_size is required for random C4 mode")
        return random_basis(q, width, basis_size, rng, include_standard=True)
    raise ValueError(f"unsupported C4 basis mode: {mode}")


def build_basis_key(
    tilde_s: list[int],
    secret_r: list[int],
    params: SableParams,
    rng: random.Random,
    *,
    block_size: int | None = None,
    basis_size: int | None = None,
    entries_per_full_block: int | None = None,
    max_terms_per_block: int = 1,
    mode: BasisMode = "projective",
    **ignored: object,
) -> C4BasisKey:
    q = params.q
    N = len(tilde_s)
    ell = params.c2_block_size if block_size is None else block_size
    if basis_size is None and entries_per_full_block is not None:
        basis_size = entries_per_full_block
    if ell <= 0:
        raise ValueError("block_size must be positive")
    if N != params.N:
        raise ValueError("tilde_s length must equal params.N")
    if len(secret_r) != params.n_c:
        raise ValueError("compaction secret length mismatch")
    bases: list[list[tuple[int, ...]]] = []
    blocks: list[list[clpn.CLPNCiphertext]] = []
    for s_block in _secret_blocks(tilde_s, ell):
        basis = _basis_for_width(q, len(s_block), rng, mode=mode, basis_size=basis_size)
        cts = [clpn.encrypt(dot_dense(vec, s_block, q), secret_r, params, rng) for vec in basis]
        bases.append(basis)
        blocks.append(cts)
    return C4BasisKey(
        q=q,
        N=N,
        block_size=ell,
        n_c=params.n_c,
        m_c=params.m_c,
        max_terms_per_block=max_terms_per_block,
        basis_mode=mode,
        bases=bases,
        blocks=blocks,
    )


def coeff_blocks(coeffs: SparseVector, block_size: int) -> list[tuple[int, ...]]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    q = coeffs.q
    return [
        tuple(coeffs.data.get(start + j, 0) % q for j in range(min(block_size, coeffs.length - start)))
        for start in range(0, coeffs.length, block_size)
    ]


def eval_lin(coeffs: SparseVector, key: C4BasisKey) -> clpn.CLPNCiphertext:
    if coeffs.length != key.N or coeffs.q != key.q:
        raise ValueError("coefficient vector incompatible with C4 key")
    acc = clpn.CLPNCiphertext.zero(key.m_c, key.n_c, key.q)
    for block_index, block_coeffs in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block_coeffs):
            continue
        comb = decompose_sparse(block_coeffs, key.bases[block_index], key.q, key.max_terms_per_block)
        for basis_index, scalar in comb.terms:
            acc = acc.add_scaled(key.blocks[block_index][basis_index], scalar)
    return acc


def compaction_term_count(coeffs: SparseVector, key: C4BasisKey) -> int:
    total = 0
    for block_index, block_coeffs in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block_coeffs):
            continue
        total += decompose_sparse(block_coeffs, key.bases[block_index], key.q, key.max_terms_per_block).weight
    return total


def active_block_count(coeffs: SparseVector, block_size: int) -> int:
    return sum(1 for block in coeff_blocks(coeffs, block_size) if any(block))


def decrypt_c4(ciphertext: clpn.CLPNCiphertext, secret_r: list[int]) -> int:
    return clpn.decrypt(ciphertext, secret_r)


def estimate_c4_key(
    params: SableParams,
    *,
    block_size: int | None = None,
    max_terms_per_block: int = 1,
    mode: BasisMode = "projective",
    basis_size: int | None = None,
    entries_per_full_block: int | None = None,
) -> dict[str, float | int | str]:
    q = params.q
    ell = params.c2_block_size if block_size is None else block_size
    if basis_size is None and entries_per_full_block is not None:
        basis_size = entries_per_full_block
    widths = [min(ell, params.N - start) for start in range(0, params.N, ell)]
    if mode == "projective":
        c4_entries = sum(projective_count(q, w) for w in widths)
    elif mode == "random":
        if basis_size is None:
            raise ValueError("basis_size/entries_per_full_block required for random mode")
        c4_entries = sum(min(basis_size, projective_count(q, w)) for w in widths)
    else:
        raise ValueError(f"unsupported C4 basis mode: {mode}")
    c2_entries = sum(q**w - 1 for w in widths)
    c4_terms_bound = len(widths) * max_terms_per_block
    eta_c4 = qary_piling_up(q, params.eta_c, c4_terms_bound)
    return {
        "params": params.name,
        "q": q,
        "N": params.N,
        "block_size": ell,
        "num_blocks": len(widths),
        "basis_mode": mode,
        "legacy_entries": params.N,
        "c2_entries": c2_entries,
        "c4_entries": c4_entries,
        "c4_vs_c2_entry_ratio": c4_entries / c2_entries if c2_entries else 0.0,
        "c4_public_clpn_rows": c4_entries * params.m_c,
        "v1_terms_dense_blocks": params.N,
        "c2_terms": len(widths),
        "c4_terms_bound": c4_terms_bound,
        "eta_c4_bound": eta_c4,
        "repetition_failure_bound_c4": repetition_failure_bound(params.m_c, eta_c4),
        "log_q_sparse_volume_full_block": log_q_sparse_volume(q, projective_count(q, min(ell, params.N)), max_terms_per_block) if mode == "projective" else 0.0,
    }


def screen_basis(
    q: int,
    width: int,
    basis: Sequence[Sequence[int]],
    max_terms: int,
    rng: random.Random,
    *,
    samples: int = 200,
    relation_weight: int = 3,
) -> dict[str, float | int | str]:
    coverage = estimate_sample_coverage(q, width, basis, max_terms, rng, samples=samples)
    relations = find_low_weight_relation(q, basis, relation_weight, limit=1)
    return {
        "q": q,
        "width": width,
        "basis_entries": len(basis),
        "max_terms": max_terms,
        "capacity_ratio": coverage_capacity(q, width, len(basis), max_terms),
        "sample_coverage_rate": coverage,
        "low_weight_relation_found": 1 if relations else 0,
        "relation_weight_screen": relation_weight,
        "comment": "diagnostic only; not a security proof",
    }


C4AdditiveBasisKey = C4BasisKey
build_c4_basis_key = build_basis_key
eval_lin_c4 = eval_lin
terms_used = compaction_term_count
term_count = compaction_term_count

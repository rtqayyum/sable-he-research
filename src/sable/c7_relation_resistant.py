"""C7 relation-resistant compaction for SABLE-HE.

C6 showed that full projective C4 dictionaries have abundant weight-3 public
relations.  C7 makes the conservative coordinate compactor the default security
profile and keeps screened random additive bases as an optional optimization.

The key design rule is simple: correctness must never depend on a complete
projective dictionary.  Every block stores the coordinate basis first, so every
coefficient block has a guaranteed representation.  Extra masks may be added
only if a local low-weight-relation screen accepts them.  If sparse
representation with the extra masks fails, compaction falls back to coordinate
terms.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Literal, Sequence

from . import clpn
from .additive_basis import (
    SparseCombination,
    decompose_sparse,
    find_low_weight_relation,
    normalize_projective,
)
from .field import dot_dense, qary_piling_up, repetition_failure_bound
from .params import SableParams
from .sparse import SparseVector

C7Mode = Literal["coordinate", "screened-random"]
Vector = tuple[int, ...]


def _mod_tuple(vec: Sequence[int], q: int) -> Vector:
    return tuple(int(x) % q for x in vec)


def standard_basis(width: int) -> list[Vector]:
    if width <= 0:
        raise ValueError("width must be positive")
    out: list[Vector] = []
    for i in range(width):
        row = [0] * width
        row[i] = 1
        out.append(tuple(row))
    return out


def hamming_weight(vec: Sequence[int], q: int) -> int:
    return sum(1 for x in vec if int(x) % q)


def _random_full_candidate(q: int, width: int, rng: random.Random, min_weight: int) -> Vector:
    for _ in range(10_000):
        v = tuple(rng.randrange(q) for _ in range(width))
        if hamming_weight(v, q) >= min_weight:
            return v
    # Deterministic fallback with requested weight.
    w = min(width, max(1, min_weight))
    return tuple([1] * w + [0] * (width - w))


def _projective_representatives_seen(basis: Sequence[Sequence[int]], q: int) -> set[Vector]:
    seen: set[Vector] = set()
    for vec in basis:
        norm = normalize_projective(vec, q)
        if norm is not None:
            seen.add(norm[1])
    return seen


def low_weight_relation_exists(q: int, basis: Sequence[Sequence[int]], max_weight: int) -> bool:
    return bool(find_low_weight_relation(q, basis, max_weight, limit=1))


def first_relation_weight(q: int, basis: Sequence[Sequence[int]], max_weight: int = 5) -> int | None:
    for w in range(1, max_weight + 1):
        if low_weight_relation_exists(q, basis, w):
            return w
    return None


def build_screened_basis(
    q: int,
    width: int,
    entries: int,
    rng: random.Random,
    *,
    min_relation_weight: int = 4,
    max_attempts: int = 20_000,
) -> list[Vector]:
    """Build a local additive basis with a low-weight-relation screen.

    The first ``width`` entries are always the coordinate basis.  Extra masks
    are added only when they do not introduce a relation of weight below
    ``min_relation_weight`` according to an exhaustive local screen.  This is a
    diagnostic screen, not a proof against all attacks.
    """
    if entries < width:
        raise ValueError("entries must be at least width for guaranteed coverage")
    basis = standard_basis(width)
    if entries == width:
        return basis

    seen_projective = _projective_representatives_seen(basis, q)
    target = entries
    attempts = 0
    min_candidate_weight = min(width, max(1, min_relation_weight - 1))
    while len(basis) < target and attempts < max_attempts:
        attempts += 1
        cand = _random_full_candidate(q, width, rng, min_candidate_weight)
        norm = normalize_projective(cand, q)
        if norm is None:
            continue
        rep = norm[1]
        if rep in seen_projective:
            continue
        trial = basis + [rep]
        if low_weight_relation_exists(q, trial, min_relation_weight - 1):
            continue
        basis.append(rep)
        seen_projective.add(rep)
    return basis


@dataclass(frozen=True)
class C7BasisKey:
    q: int
    N: int
    block_size: int
    n_c: int
    m_c: int
    mode: str
    preferred_terms_per_block: int
    relation_screen_weight: int
    bases: list[list[Vector]]
    blocks: list[list[clpn.CLPNCiphertext]]

    def __post_init__(self) -> None:
        if self.N <= 0 or self.block_size <= 0:
            raise ValueError("invalid C7 dimensions")
        expected = math.ceil(self.N / self.block_size)
        if len(self.bases) != expected or len(self.blocks) != expected:
            raise ValueError("incorrect number of C7 blocks")
        for block_index, (basis, cts) in enumerate(zip(self.bases, self.blocks)):
            width = self.block_width(block_index)
            if len(basis) != len(cts):
                raise ValueError("basis/ciphertext count mismatch")
            if len(basis) < width:
                raise ValueError("basis must contain at least the coordinate vectors")
            if list(basis[:width]) != standard_basis(width):
                raise ValueError("first width C7 basis vectors must be the coordinate basis")
            for vec, ct in zip(basis, cts):
                if len(vec) != width:
                    raise ValueError("basis vector width mismatch")
                if all((x % self.q) == 0 for x in vec):
                    raise ValueError("zero basis vector is not allowed")
                if ct.q != self.q or ct.n != self.n_c or ct.m != self.m_c:
                    raise ValueError("CLPN ciphertext incompatible with C7 key")

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

    @property
    def worst_case_terms_dense_row(self) -> int:
        return self.N

    def block_width(self, block_index: int) -> int:
        start = block_index * self.block_size
        return max(0, min(self.block_size, self.N - start))


def _secret_blocks(tilde_s: list[int], block_size: int) -> list[list[int]]:
    return [tilde_s[start : start + block_size] for start in range(0, len(tilde_s), block_size)]


def build_basis_key(
    tilde_s: list[int],
    secret_r: list[int],
    params: SableParams,
    rng: random.Random,
    *,
    block_size: int | None = None,
    mode: C7Mode = "coordinate",
    entries_per_block: int | None = None,
    preferred_terms_per_block: int | None = None,
    relation_screen_weight: int = 4,
) -> C7BasisKey:
    q = params.q
    N = len(tilde_s)
    ell = params.c2_block_size if block_size is None else block_size
    if ell <= 0:
        raise ValueError("block_size must be positive")
    if N != params.N:
        raise ValueError("tilde_s length must equal params.N")
    if len(secret_r) != params.n_c:
        raise ValueError("compaction secret length mismatch")

    bases: list[list[Vector]] = []
    blocks: list[list[clpn.CLPNCiphertext]] = []
    for s_block in _secret_blocks(tilde_s, ell):
        width = len(s_block)
        if mode == "coordinate":
            basis = standard_basis(width)
        elif mode == "screened-random":
            entries = max(width, entries_per_block or (width + 2))
            basis = build_screened_basis(
                q,
                width,
                entries,
                rng,
                min_relation_weight=relation_screen_weight,
            )
        else:
            raise ValueError(f"unsupported C7 mode: {mode}")
        cts = [clpn.encrypt(dot_dense(vec, s_block, q), secret_r, params, rng) for vec in basis]
        bases.append(basis)
        blocks.append(cts)

    preferred = preferred_terms_per_block
    if preferred is None:
        preferred = 1 if mode == "screened-random" else ell
    return C7BasisKey(
        q=q,
        N=N,
        block_size=ell,
        n_c=params.n_c,
        m_c=params.m_c,
        mode=mode,
        preferred_terms_per_block=preferred,
        relation_screen_weight=relation_screen_weight,
        bases=bases,
        blocks=blocks,
    )


def coeff_blocks(coeffs: SparseVector, block_size: int) -> list[Vector]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    q = coeffs.q
    return [
        tuple(coeffs.data.get(start + j, 0) % q for j in range(min(block_size, coeffs.length - start)))
        for start in range(0, coeffs.length, block_size)
    ]


def coordinate_combination(target: Sequence[int], q: int) -> SparseCombination:
    terms = tuple((i, int(c) % q) for i, c in enumerate(target) if int(c) % q)
    return SparseCombination(len(target), q, terms)


def decompose_c7(target: Sequence[int], basis: Sequence[Sequence[int]], q: int, preferred_terms: int) -> SparseCombination:
    t = _mod_tuple(target, q)
    if not any(t):
        return SparseCombination(len(t), q, tuple())
    # First try the screened/additive masks up to the preferred bound.
    if preferred_terms > 0:
        try:
            return decompose_sparse(t, basis, q, preferred_terms)
        except ValueError:
            pass
    # Guaranteed fallback: the first width vectors are the coordinate basis.
    return coordinate_combination(t, q)


def eval_lin(coeffs: SparseVector, key: C7BasisKey) -> clpn.CLPNCiphertext:
    if coeffs.length != key.N or coeffs.q != key.q:
        raise ValueError("coefficient vector incompatible with C7 key")
    acc = clpn.CLPNCiphertext.zero(key.m_c, key.n_c, key.q)
    for block_index, block_coeffs in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block_coeffs):
            continue
        comb = decompose_c7(block_coeffs, key.bases[block_index], key.q, key.preferred_terms_per_block)
        for basis_index, scalar in comb.terms:
            acc = acc.add_scaled(key.blocks[block_index][basis_index], scalar)
    return acc


def compaction_term_count(coeffs: SparseVector, key: C7BasisKey) -> int:
    total = 0
    for block_index, block_coeffs in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block_coeffs):
            continue
        total += decompose_c7(block_coeffs, key.bases[block_index], key.q, key.preferred_terms_per_block).weight
    return total


def decrypt_c7(ciphertext: clpn.CLPNCiphertext, secret_r: list[int]) -> int:
    return clpn.decrypt(ciphertext, secret_r)


def block_relation_profile(q: int, basis: Sequence[Sequence[int]], screen_weight: int = 3) -> dict[str, int | str | None]:
    first = first_relation_weight(q, basis, max_weight=screen_weight)
    if first is None:
        verdict = f"no relation found up to weight {screen_weight}"
    else:
        verdict = f"relation found at weight {first}"
    return {
        "entries": len(basis),
        "width": len(basis[0]) if basis else 0,
        "first_relation_weight_up_to_screen": first,
        "screen_weight": screen_weight,
        "verdict": verdict,
    }


def estimate_c7_key(
    params: SableParams,
    *,
    block_size: int | None = None,
    mode: C7Mode = "coordinate",
    entries_per_block: int | None = None,
    preferred_terms_per_block: int | None = None,
    relation_screen_weight: int = 4,
) -> dict[str, float | int | str]:
    q = params.q
    ell = params.c2_block_size if block_size is None else block_size
    widths = [min(ell, params.N - start) for start in range(0, params.N, ell)]
    if mode == "coordinate":
        entries = sum(widths)
        preferred = ell if preferred_terms_per_block is None else preferred_terms_per_block
        relation_note = "coordinate blocks are linearly independent; no within-block kernel relations"
    elif mode == "screened-random":
        entries = sum(max(w, entries_per_block or (w + 2)) for w in widths)
        preferred = 1 if preferred_terms_per_block is None else preferred_terms_per_block
        relation_note = "screened random mode is experimental; use generated basis screens"
    else:
        raise ValueError(f"unsupported C7 mode: {mode}")
    dense_terms_bound = params.N
    preferred_terms_bound = len(widths) * preferred
    eta_dense = qary_piling_up(q, params.eta_c, dense_terms_bound)
    eta_preferred = qary_piling_up(q, params.eta_c, preferred_terms_bound)
    return {
        "params": params.name,
        "q": q,
        "N": params.N,
        "block_size": ell,
        "num_blocks": len(widths),
        "mode": mode,
        "public_entries": entries,
        "public_clpn_rows": entries * params.m_c,
        "public_field_elements_dense": entries * params.m_c * (params.n_c + 1),
        "preferred_terms_bound": preferred_terms_bound,
        "dense_fallback_terms_bound": dense_terms_bound,
        "eta_preferred_bound": eta_preferred,
        "eta_dense_fallback_bound": eta_dense,
        "repetition_failure_bound_preferred": repetition_failure_bound(params.m_c, eta_preferred),
        "repetition_failure_bound_dense_fallback": repetition_failure_bound(params.m_c, eta_dense),
        "relation_screen_weight": relation_screen_weight,
        "relation_note": relation_note,
        "security_status": "main research default" if mode == "coordinate" else "experimental optimization",
    }


def readiness_summary(params: SableParams) -> dict[str, object]:
    coord = estimate_c7_key(params, block_size=1, mode="coordinate")
    return {
        "version": "v0.9-C7",
        "status": "ready as a research prototype and manuscript package",
        "not_ready_for": [
            "production deployment",
            "standardization claims",
            "certified concrete security without independent LPN estimation",
        ],
        "main_candidate": "C7 coordinate relation-resistant compaction",
        "experimental_candidates": ["C7 screened-random additive masks", "C4 projective compaction", "C2/C3 dictionaries"],
        "default_estimate": coord,
        "stop_condition_met": True,
        "remaining_open_science_questions": [
            "tight sparse/q-ary LPN estimator with large public sample surfaces",
            "stronger error-correcting compactor beyond repetition decoding",
            "measured OpenFHE/TFHE/BFV/BGV/CKKS benchmarks on identical circuits",
        ],
    }


# Backward-friendly aliases.
C7RelationResistantKey = C7BasisKey
build_c7_basis_key = build_basis_key
eval_lin_c7 = eval_lin
terms_used = compaction_term_count

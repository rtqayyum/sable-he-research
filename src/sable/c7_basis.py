"""C7 screened additive-basis utilities.

C7 is the conservative replacement for the vulnerable C4 full-projective
compactor.  It keeps a universal coordinate fallback by always publishing the
standard basis e_1,...,e_b for each block.  Optional random masks are accepted
only when they pass a low-weight relation screen, in particular no projective
duplicates and no weight-3 dependencies with already-published masks.

This module is deliberately small and auditable.  The screening routines are
not a proof of security; they are a construction-time rejection filter that
prevents the abundant projective-line relation surface discovered in C6.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from typing import Iterable, Sequence

from .additive_basis import SparseCombination, decompose_sparse, normalize_projective

Vector = tuple[int, ...]


def mod_tuple(vec: Sequence[int] | Iterable[int], q: int) -> Vector:
    return tuple(int(x) % q for x in vec)


def hamming_weight(vec: Sequence[int], q: int) -> int:
    return sum(1 for x in vec if int(x) % q != 0)


def standard_basis(q: int, width: int) -> list[Vector]:
    if q <= 1:
        raise ValueError("q must be at least 2")
    if width <= 0:
        raise ValueError("width must be positive")
    out: list[Vector] = []
    for i in range(width):
        row = [0] * width
        row[i] = 1
        out.append(tuple(row))
    return out


def random_nonzero_vector(q: int, width: int, rng: random.Random) -> Vector:
    while True:
        v = tuple(rng.randrange(q) for _ in range(width))
        if any(v):
            return v


def rank_mod_q(rows: Sequence[Sequence[int]], q: int) -> int:
    """Rank of a small matrix over F_q."""
    if q <= 1:
        raise ValueError("q must be at least 2")
    mat = [list(mod_tuple(r, q)) for r in rows if any(int(x) % q for x in r)]
    if not mat:
        return 0
    ncols = len(mat[0])
    for r in mat:
        if len(r) != ncols:
            raise ValueError("row length mismatch")
    rank = 0
    col = 0
    while rank < len(mat) and col < ncols:
        pivot = None
        for r in range(rank, len(mat)):
            if mat[r][col] % q:
                pivot = r
                break
        if pivot is None:
            col += 1
            continue
        mat[rank], mat[pivot] = mat[pivot], mat[rank]
        inv = pow(mat[rank][col] % q, -1, q)
        mat[rank] = [(x * inv) % q for x in mat[rank]]
        for r in range(len(mat)):
            if r == rank:
                continue
            factor = mat[r][col] % q
            if factor:
                mat[r] = [(x - factor * y) % q for x, y in zip(mat[r], mat[rank])]
        rank += 1
        col += 1
    return rank


def has_projective_duplicate(basis: Sequence[Sequence[int]], candidate: Sequence[int], q: int) -> bool:
    norm_c = normalize_projective(candidate, q)
    if norm_c is None:
        return True
    rep_c = norm_c[1]
    for vec in basis:
        norm = normalize_projective(vec, q)
        if norm is not None and norm[1] == rep_c:
            return True
    return False


def creates_weight3_relation(basis: Sequence[Sequence[int]], candidate: Sequence[int], q: int) -> bool:
    """Return True if candidate participates in a three-term dependency.

    For nonzero, non-projectively-duplicate vectors, a weight-3 dependency with
    candidate exists exactly when candidate and two existing vectors have rank
    at most two.
    """
    c = mod_tuple(candidate, q)
    if hamming_weight(c, q) == 0:
        return True
    for u, v in itertools.combinations(basis, 2):
        if rank_mod_q([u, v, c], q) <= 2:
            return True
    return False


def find_weight3_relation(basis: Sequence[Sequence[int]], q: int) -> tuple[int, int, int] | None:
    for i, j, k in itertools.combinations(range(len(basis)), 3):
        if rank_mod_q([basis[i], basis[j], basis[k]], q) <= 2:
            return (i, j, k)
    return None


def find_weight2_relation(basis: Sequence[Sequence[int]], q: int) -> tuple[int, int] | None:
    seen: dict[Vector, int] = {}
    for idx, vec in enumerate(basis):
        norm = normalize_projective(vec, q)
        if norm is None:
            return (idx, idx)
        rep = norm[1]
        if rep in seen:
            return (seen[rep], idx)
        seen[rep] = idx
    return None


@dataclass(frozen=True)
class ScreenedBasisResult:
    q: int
    width: int
    basis: list[Vector]
    requested_extra_masks: int
    accepted_extra_masks: int
    rejected_projective_duplicates: int
    rejected_low_support: int
    rejected_weight3: int
    attempts: int
    min_mask_support: int
    forbid_weight3: bool

    @property
    def entries(self) -> int:
        return len(self.basis)

    @property
    def guaranteed_coverage_terms(self) -> int:
        # Because the standard basis is always included, every target vector in
        # F_q^width decomposes into at most width terms.
        return self.width

    @property
    def has_weight2_relation(self) -> bool:
        return find_weight2_relation(self.basis, self.q) is not None

    @property
    def has_weight3_relation(self) -> bool:
        return find_weight3_relation(self.basis, self.q) is not None

    def to_jsonable(self) -> dict[str, int | bool]:
        return {
            "q": self.q,
            "width": self.width,
            "basis_entries": self.entries,
            "requested_extra_masks": self.requested_extra_masks,
            "accepted_extra_masks": self.accepted_extra_masks,
            "rejected_projective_duplicates": self.rejected_projective_duplicates,
            "rejected_low_support": self.rejected_low_support,
            "rejected_weight3": self.rejected_weight3,
            "attempts": self.attempts,
            "min_mask_support": self.min_mask_support,
            "forbid_weight3": self.forbid_weight3,
            "guaranteed_coverage_terms": self.guaranteed_coverage_terms,
            "has_weight2_relation": self.has_weight2_relation,
            "has_weight3_relation": self.has_weight3_relation,
        }


def build_screened_basis(
    q: int,
    width: int,
    rng: random.Random,
    *,
    extra_masks: int = 0,
    min_mask_support: int = 3,
    forbid_weight3: bool = True,
    max_attempts: int = 10000,
) -> ScreenedBasisResult:
    if width <= 0:
        raise ValueError("width must be positive")
    if extra_masks < 0:
        raise ValueError("extra_masks must be nonnegative")
    if min_mask_support < 1:
        raise ValueError("min_mask_support must be positive")
    basis = standard_basis(q, width)
    accepted = 0
    rejected_dup = 0
    rejected_support = 0
    rejected_w3 = 0
    attempts = 0
    # If min_mask_support > width, extras are impossible; return the safe
    # coordinate basis immediately after a bounded accounting attempt.
    while accepted < extra_masks and attempts < max_attempts:
        attempts += 1
        cand = random_nonzero_vector(q, width, rng)
        if hamming_weight(cand, q) < min_mask_support:
            rejected_support += 1
            continue
        if has_projective_duplicate(basis, cand, q):
            rejected_dup += 1
            continue
        if forbid_weight3 and creates_weight3_relation(basis, cand, q):
            rejected_w3 += 1
            continue
        basis.append(cand)
        accepted += 1
    return ScreenedBasisResult(
        q=q,
        width=width,
        basis=basis,
        requested_extra_masks=extra_masks,
        accepted_extra_masks=accepted,
        rejected_projective_duplicates=rejected_dup,
        rejected_low_support=rejected_support,
        rejected_weight3=rejected_w3,
        attempts=attempts,
        min_mask_support=min_mask_support,
        forbid_weight3=forbid_weight3,
    )


def decompose_with_coordinate_fallback(
    target: Sequence[int],
    basis: Sequence[Sequence[int]],
    q: int,
    max_terms: int,
) -> SparseCombination:
    """Decompose target with basis, falling back to standard coordinates.

    The first `width` basis vectors are required to be the standard basis.  This
    gives universal correctness with at most width terms even if optional masks
    do not help.
    """
    width = len(target)
    if max_terms < 0:
        raise ValueError("max_terms must be nonnegative")
    t = mod_tuple(target, q)
    if all(x == 0 for x in t):
        return SparseCombination(width, q, tuple())
    try:
        return decompose_sparse(t, basis, q, max_terms)
    except ValueError:
        terms = tuple((i, coeff) for i, coeff in enumerate(t) if coeff % q)
        if len(terms) <= max_terms:
            return SparseCombination(width, q, terms)
        raise

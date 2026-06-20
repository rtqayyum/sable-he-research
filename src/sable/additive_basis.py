"""Sparse additive-basis tools for SABLE-HE-C4.

C4 replaces the full C2/C3 block dictionary by a smaller public codebook of
block masks.  For a block secret s_B in F_q^b, the public key stores CLPN
ciphertexts of <u_j, s_B>.  During compaction, a coefficient block alpha is
represented as a sparse linear combination alpha = sum_j z_j u_j.

The default basis is projective: one representative of every one-dimensional
line in F_q^b.  Every nonzero alpha has a weight-one representation, while the
public entries drop from q^b - 1 to (q^b - 1)/(q - 1).
"""

from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass
from typing import Iterable, Sequence

Vector = tuple[int, ...]


def _mod_tuple(vec: Sequence[int] | Iterable[int], q: int) -> Vector:
    return tuple(int(x) % q for x in vec)


def _zero(width: int) -> Vector:
    return tuple(0 for _ in range(width))


def add_vec(a: Sequence[int], b: Sequence[int], q: int) -> Vector:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return tuple((int(x) + int(y)) % q for x, y in zip(a, b))


def sub_vec(a: Sequence[int], b: Sequence[int], q: int) -> Vector:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return tuple((int(x) - int(y)) % q for x, y in zip(a, b))


def scale_vec(alpha: int, vec: Sequence[int], q: int) -> Vector:
    a = int(alpha) % q
    return tuple((a * int(x)) % q for x in vec)


def inv_mod(a: int, q: int) -> int:
    a %= q
    if a == 0:
        raise ZeroDivisionError("zero has no inverse")
    return pow(a, -1, q)


def first_nonzero(vec: Sequence[int], q: int) -> tuple[int, int] | None:
    for idx, value in enumerate(vec):
        v = int(value) % q
        if v:
            return idx, v
    return None


def normalize_projective(vec: Sequence[int], q: int) -> tuple[int, Vector] | None:
    """Return (scale, representative) such that vec = scale * representative."""
    v = _mod_tuple(vec, q)
    pivot = first_nonzero(v, q)
    if pivot is None:
        return None
    _, scale = pivot
    rep = scale_vec(inv_mod(scale, q), v, q)
    return scale, rep


def projective_representatives(q: int, width: int) -> list[Vector]:
    """One representative of each one-dimensional subspace of F_q^width."""
    if q < 2:
        raise ValueError("q must be at least two")
    if width <= 0:
        raise ValueError("width must be positive")
    reps: list[Vector] = []
    for pivot in range(width):
        prefix = [0] * pivot + [1]
        suffix_len = width - pivot - 1
        for suffix in itertools.product(range(q), repeat=suffix_len):
            reps.append(tuple(prefix + list(suffix)))
    return reps


def projective_count(q: int, width: int) -> int:
    if width <= 0:
        return 0
    return (q**width - 1) // (q - 1)


def random_basis(
    q: int,
    width: int,
    entries: int,
    rng: random.Random,
    *,
    include_standard: bool = True,
    projective_unique: bool = True,
) -> list[Vector]:
    """Generate an experimental random additive codebook."""
    if entries <= 0:
        raise ValueError("entries must be positive")
    if width <= 0:
        raise ValueError("width must be positive")
    basis: list[Vector] = []
    seen: set[Vector] = set()
    seen_projective: set[Vector] = set()

    def add_candidate(vec: Sequence[int]) -> None:
        v = _mod_tuple(vec, q)
        if all(x == 0 for x in v):
            return
        if v in seen:
            return
        if projective_unique:
            norm = normalize_projective(v, q)
            if norm is not None and norm[1] in seen_projective:
                return
            if norm is not None:
                seen_projective.add(norm[1])
        seen.add(v)
        basis.append(v)

    if include_standard:
        for i in range(width):
            e = [0] * width
            e[i] = 1
            add_candidate(e)
            if len(basis) >= entries:
                return basis

    max_possible = projective_count(q, width) if projective_unique else q**width - 1
    target = min(entries, max_possible)
    attempts = 0
    while len(basis) < target and attempts < 100 * max(1, target):
        attempts += 1
        add_candidate([rng.randrange(q) for _ in range(width)])
    if len(basis) < target:
        for rep in projective_representatives(q, width):
            add_candidate(rep)
            if len(basis) >= target:
                break
    return basis


@dataclass(frozen=True)
class SparseCombination:
    width: int
    q: int
    terms: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        cleaned: list[tuple[int, int]] = []
        seen: set[int] = set()
        for idx, coeff in self.terms:
            i = int(idx)
            c = int(coeff) % self.q
            if c == 0:
                continue
            if i in seen:
                raise ValueError("duplicate basis index")
            seen.add(i)
            cleaned.append((i, c))
        object.__setattr__(self, "terms", tuple(cleaned))

    @property
    def weight(self) -> int:
        return len(self.terms)

    def evaluate(self, basis: Sequence[Sequence[int]]) -> Vector:
        acc = [0] * self.width
        for idx, coeff in self.terms:
            vec = basis[idx]
            if len(vec) != self.width:
                raise ValueError("basis vector width mismatch")
            for j in range(self.width):
                acc[j] = (acc[j] + coeff * int(vec[j])) % self.q
        return tuple(acc)


def _enumerate_sums(
    basis: Sequence[Sequence[int]],
    indices: Sequence[int],
    q: int,
    max_weight: int,
    max_states: int,
) -> dict[Vector, tuple[tuple[int, int], ...]]:
    width = len(basis[0])
    out: dict[Vector, tuple[tuple[int, int], ...]] = {_zero(width): tuple()}
    states = 1
    for w in range(1, min(max_weight, len(indices)) + 1):
        for combo in itertools.combinations(indices, w):
            for coeffs in itertools.product(range(1, q), repeat=w):
                acc = [0] * width
                terms = []
                for idx, coeff in zip(combo, coeffs):
                    terms.append((idx, coeff))
                    vec = basis[idx]
                    for j in range(width):
                        acc[j] = (acc[j] + coeff * int(vec[j])) % q
                out.setdefault(tuple(acc), tuple(terms))
                states += 1
                if states >= max_states:
                    return out
    return out


def decompose_sparse(
    target: Sequence[int],
    basis: Sequence[Sequence[int]],
    q: int,
    max_weight: int,
    *,
    max_states: int = 250_000,
) -> SparseCombination:
    """Find a sparse representation of target using the basis."""
    if max_weight < 0:
        raise ValueError("max_weight must be nonnegative")
    if not basis:
        raise ValueError("basis cannot be empty")
    width = len(basis[0])
    t = _mod_tuple(target, q)
    if len(t) != width:
        raise ValueError("target width mismatch")
    if all(x == 0 for x in t):
        return SparseCombination(width, q, tuple())
    if max_weight == 0:
        raise ValueError("nonzero target cannot be represented with weight zero")

    projective: dict[Vector, int] = {}
    for idx, vec in enumerate(basis):
        norm = normalize_projective(vec, q)
        if norm is not None:
            projective.setdefault(norm[1], idx)
    norm_t = normalize_projective(t, q)
    if norm_t is not None:
        scale, rep = norm_t
        idx = projective.get(rep)
        if idx is not None:
            pivot = first_nonzero(basis[idx], q)
            if pivot is None:
                raise AssertionError("zero basis vector")
            coeff = scale * inv_mod(pivot[1], q)
            return SparseCombination(width, q, ((idx, coeff),))

    M = len(basis)
    left = list(range(0, M // 2))
    right = list(range(M // 2, M))
    left_max = max_weight // 2
    right_max = max_weight - left_max
    left_sums = _enumerate_sums(basis, left, q, left_max, max_states)
    right_sums = _enumerate_sums(basis, right, q, right_max, max_states)
    for lsum, lterms in left_sums.items():
        need = sub_vec(t, lsum, q)
        rterms = right_sums.get(need)
        if rterms is not None and len(lterms) + len(rterms) <= max_weight:
            return SparseCombination(width, q, tuple(lterms) + tuple(rterms))

    for w in range(1, min(max_weight, M) + 1):
        for combo in itertools.combinations(range(M), w):
            for coeffs in itertools.product(range(1, q), repeat=w):
                acc = [0] * width
                for idx, coeff in zip(combo, coeffs):
                    vec = basis[idx]
                    for j in range(width):
                        acc[j] = (acc[j] + coeff * int(vec[j])) % q
                if tuple(acc) == t:
                    return SparseCombination(width, q, tuple((i, c) for i, c in zip(combo, coeffs)))
    raise ValueError("no sparse representation found within search bound")


def sparse_combination_count(q: int, M: int, T: int) -> int:
    if q <= 1 or M < 0 or T < 0:
        raise ValueError("invalid parameters")
    return sum(math.comb(M, w) * (q - 1) ** w for w in range(0, min(M, T) + 1))


def log_q_sparse_volume(q: int, M: int, T: int) -> float:
    vol = sparse_combination_count(q, M, T)
    return math.log(vol, q) if vol > 0 else float("-inf")


def coverage_capacity(q: int, width: int, M: int, T: int) -> float:
    return min(1.0, sparse_combination_count(q, M, T) / (q**width))


def estimate_sample_coverage(
    q: int,
    width: int,
    basis: Sequence[Sequence[int]],
    max_weight: int,
    rng: random.Random,
    *,
    samples: int = 200,
) -> float:
    if samples <= 0:
        raise ValueError("samples must be positive")
    hits = 0
    for _ in range(samples):
        target = tuple(rng.randrange(q) for _ in range(width))
        try:
            decompose_sparse(target, basis, q, max_weight)
            hits += 1
        except ValueError:
            pass
    return hits / samples


def find_low_weight_relation(
    q: int,
    basis: Sequence[Sequence[int]],
    max_weight: int,
    *,
    limit: int = 1,
) -> list[SparseCombination]:
    if not basis:
        return []
    width = len(basis[0])
    found: list[SparseCombination] = []
    for w in range(1, min(max_weight, len(basis)) + 1):
        for idxs in itertools.combinations(range(len(basis)), w):
            for coeffs in itertools.product(range(1, q), repeat=w):
                comb = SparseCombination(width, q, tuple((i, c) for i, c in zip(idxs, coeffs)))
                if comb.evaluate(basis) == _zero(width):
                    found.append(comb)
                    if len(found) >= limit:
                        return found
    return found

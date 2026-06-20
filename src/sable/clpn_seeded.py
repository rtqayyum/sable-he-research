"""Seeded q-ary LPN/code linearly homomorphic compaction layer.

The ordinary CLPN prototype stores a dense matrix A and vector b.  In seeded
CLPN, each A matrix is generated from a public seed.  A ciphertext stores only
its b-vector and a list of seeded A terms.  This is a storage optimization, not
a security optimization: the public LPN sample surface is unchanged because the
A rows are still public and efficiently derivable.
"""

from __future__ import annotations

import hashlib
import random
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from .field import dot_dense, sample_noise
from .params import SableParams


def _seed_bytes(seed: int) -> bytes:
    if seed < 0:
        raise ValueError("seed must be nonnegative")
    return seed.to_bytes(32, "big", signed=False)


def derive_entry(seed: int, row: int, col: int, q: int) -> int:
    """Derive one F_q matrix entry from a public seed.

    This uses SHA-256 as a deterministic expander for the research prototype.
    It is not intended as a constant-time or certified DRBG implementation.
    """
    if row < 0 or col < 0:
        raise ValueError("row/col must be nonnegative")
    data = _seed_bytes(seed) + row.to_bytes(8, "big") + col.to_bytes(8, "big")
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q


def derive_row(seed: int, row: int, n: int, q: int) -> list[int]:
    return [derive_entry(seed, row, col, q) for col in range(n)]


def _normalize_terms(terms: Iterable[tuple[int, int]], q: int) -> tuple[tuple[int, int], ...]:
    merged: dict[int, int] = {}
    for coeff, seed in terms:
        c = coeff % q
        if c == 0:
            continue
        merged[seed] = (merged.get(seed, 0) + c) % q
        if merged[seed] == 0:
            del merged[seed]
    return tuple((coeff, seed) for seed, coeff in sorted(merged.items(), key=lambda item: item[0]))


@dataclass(frozen=True)
class SeededCLPNCiphertext:
    """Seeded CLPN ciphertext for a scalar over F_q.

    The matrix component is represented as a linear combination of public seeds:
        A = sum_j alpha_j A(seed_j).
    The vector b is stored explicitly.  Decryption derives each A(seed_j) row on
    demand and subtracts A r from b before plurality decoding.
    """

    b: list[int]
    q: int
    n: int
    terms: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if self.q <= 1:
            raise ValueError("q must be at least 2")
        if self.n <= 0:
            raise ValueError("n must be positive")
        if not self.b:
            raise ValueError("b cannot be empty")
        object.__setattr__(self, "b", [x % self.q for x in self.b])
        object.__setattr__(self, "terms", _normalize_terms(self.terms, self.q))

    @property
    def m(self) -> int:
        return len(self.b)

    @classmethod
    def zero(cls, m: int, n: int, q: int) -> "SeededCLPNCiphertext":
        if m <= 0:
            raise ValueError("m must be positive")
        return cls([0] * m, q, n, tuple())

    @classmethod
    def fresh(cls, b: list[int], q: int, n: int, seed: int) -> "SeededCLPNCiphertext":
        return cls(b, q, n, ((1, seed),))

    def add_scaled(self, other: "SeededCLPNCiphertext", alpha: int) -> "SeededCLPNCiphertext":
        if self.q != other.q or self.n != other.n or self.m != other.m:
            raise ValueError("incompatible seeded CLPN ciphertexts")
        a = alpha % self.q
        if a == 0:
            return self
        b = [(x + a * y) % self.q for x, y in zip(self.b, other.b)]
        terms = self.terms + tuple(((a * coeff) % self.q, seed) for coeff, seed in other.terms)
        return SeededCLPNCiphertext(b, self.q, self.n, terms)

    def add(self, other: "SeededCLPNCiphertext") -> "SeededCLPNCiphertext":
        return self.add_scaled(other, 1)

    def scale(self, alpha: int) -> "SeededCLPNCiphertext":
        a = alpha % self.q
        return SeededCLPNCiphertext([(a * x) % self.q for x in self.b], self.q, self.n,
                                    tuple(((a * coeff) % self.q, seed) for coeff, seed in self.terms))

    def aggregate_row(self, row_index: int) -> list[int]:
        """Materialize one aggregate A-row for debugging and tests."""
        if row_index < 0 or row_index >= self.m:
            raise IndexError(row_index)
        out = [0] * self.n
        for coeff, seed in self.terms:
            row = derive_row(seed, row_index, self.n, self.q)
            for j, value in enumerate(row):
                out[j] = (out[j] + coeff * value) % self.q
        return out


def encrypt(x: int, secret_r: list[int], params: SableParams, rng: random.Random, *, seed: int | None = None) -> SeededCLPNCiphertext:
    """Encrypt scalar x using public-seeded q-ary LPN repetition coding."""
    q = params.q
    if len(secret_r) != params.n_c:
        raise ValueError("secret length mismatch")
    if seed is None:
        seed = rng.getrandbits(256)
    b: list[int] = []
    for row_index in range(params.m_c):
        row = derive_row(seed, row_index, params.n_c, q)
        e = sample_noise(q, params.eta_c, rng)
        b.append((dot_dense(row, secret_r, q) + x + e) % q)
    return SeededCLPNCiphertext.fresh(b, q, params.n_c, seed)


def decrypt(ciphertext: SeededCLPNCiphertext, secret_r: list[int]) -> int:
    """Plurality-decode b - A r for seeded aggregate A."""
    if len(secret_r) != ciphertext.n:
        raise ValueError("secret length mismatch")
    residuals: list[int] = []
    for row_index, bb in enumerate(ciphertext.b):
        ar = 0
        for coeff, seed in ciphertext.terms:
            row = derive_row(seed, row_index, ciphertext.n, ciphertext.q)
            ar = (ar + coeff * dot_dense(row, secret_r, ciphertext.q)) % ciphertext.q
        residuals.append((bb - ar) % ciphertext.q)
    counts = Counter(residuals)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]

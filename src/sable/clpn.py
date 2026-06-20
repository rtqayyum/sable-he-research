"""q-ary LPN/code linearly homomorphic compaction layer."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass

from .field import dot_dense, sample_noise
from .params import SableParams
from .sparse import SparseVector


@dataclass(frozen=True)
class CLPNCiphertext:
    """Dense toy CLPN ciphertext (A, b) over F_q.

    This prototype uses repetition coding: b - A r = x * 1 + error.
    """

    A: list[list[int]]
    b: list[int]
    q: int

    def __post_init__(self) -> None:
        if not self.A:
            raise ValueError("A cannot be empty")
        if len(self.A) != len(self.b):
            raise ValueError("row count mismatch")
        ncols = len(self.A[0])
        for row in self.A:
            if len(row) != ncols:
                raise ValueError("A rows must have equal length")
        object.__setattr__(self, "A", [[x % self.q for x in row] for row in self.A])
        object.__setattr__(self, "b", [x % self.q for x in self.b])

    @property
    def m(self) -> int:
        return len(self.b)

    @property
    def n(self) -> int:
        return len(self.A[0])

    @classmethod
    def zero(cls, m: int, n: int, q: int) -> "CLPNCiphertext":
        return cls([[0] * n for _ in range(m)], [0] * m, q)

    def scale(self, alpha: int) -> "CLPNCiphertext":
        a = alpha % self.q
        return CLPNCiphertext(
            [[(a * x) % self.q for x in row] for row in self.A],
            [(a * x) % self.q for x in self.b],
            self.q,
        )

    def add_scaled(self, other: "CLPNCiphertext", alpha: int) -> "CLPNCiphertext":
        if self.q != other.q or self.m != other.m or self.n != other.n:
            raise ValueError("incompatible CLPN ciphertexts")
        a = alpha % self.q
        if a == 0:
            return self
        A = []
        for row_self, row_other in zip(self.A, other.A):
            A.append([(x + a * y) % self.q for x, y in zip(row_self, row_other)])
        b = [(x + a * y) % self.q for x, y in zip(self.b, other.b)]
        return CLPNCiphertext(A, b, self.q)

    def add(self, other: "CLPNCiphertext") -> "CLPNCiphertext":
        return self.add_scaled(other, 1)


def encrypt(x: int, secret_r: list[int], params: SableParams, rng: random.Random) -> CLPNCiphertext:
    """Encrypt scalar x under q-ary LPN repetition-code compactor."""
    q = params.q
    if len(secret_r) != params.n_c:
        raise ValueError("secret length mismatch")
    A: list[list[int]] = []
    b: list[int] = []
    for _ in range(params.m_c):
        row = [rng.randrange(q) for _ in range(params.n_c)]
        e = sample_noise(q, params.eta_c, rng)
        A.append(row)
        b.append((dot_dense(row, secret_r, q) + x + e) % q)
    return CLPNCiphertext(A, b, q)


def decrypt(ciphertext: CLPNCiphertext, secret_r: list[int]) -> int:
    """Plurality-decode b - A r."""
    if len(secret_r) != ciphertext.n:
        raise ValueError("secret length mismatch")
    residuals = [
        (bb - dot_dense(row, secret_r, ciphertext.q)) % ciphertext.q
        for row, bb in zip(ciphertext.A, ciphertext.b)
    ]
    counts = Counter(residuals)
    # Deterministic tie-breaking by value for reproducibility.
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def eval_lin(coeffs: SparseVector, key: list[CLPNCiphertext]) -> CLPNCiphertext:
    """Linearly evaluate sum_i coeffs_i * key_i."""
    if len(key) != coeffs.length:
        raise ValueError("key length mismatch")
    if not key:
        raise ValueError("empty CLPN key")
    first = key[0]
    acc = CLPNCiphertext.zero(first.m, first.n, first.q)
    for i, coeff in coeffs.data.items():
        acc = acc.add_scaled(key[i], coeff)
    return acc

"""Sparse-LPN Regev-style compact input encryption."""

from __future__ import annotations

import random

from .field import sample_dense_vector, sample_noise
from .params import SableParams
from .sparse import SparseVector, sample_sparse_prefix


def extended_secret(secret: list[int], q: int) -> list[int]:
    """Return tilde{s}=(-s,1)."""
    return [(-x) % q for x in secret] + [1]


def sample_secret(length: int, q: int, rng: random.Random) -> list[int]:
    return sample_dense_vector(length, q, rng)


def encrypt(mu: int, secret_t: list[int], params: SableParams, rng: random.Random) -> SparseVector:
    """Encrypt a scalar message under the compact sparse-LPN layer."""
    if len(secret_t) != params.n:
        raise ValueError("secret length mismatch")
    q = params.q
    a = sample_sparse_prefix(params.N, params.n, params.k, q, rng)
    dot_at = sum((coeff * secret_t[i]) % q for i, coeff in a.data.items()) % q
    e = sample_noise(q, params.eta, rng)
    b = (dot_at + mu + e) % q
    data = dict(a.data)
    if b:
        data[params.n] = b
    return SparseVector(params.N, data, q)


def decrypt_raw(ciphertext: SparseVector, secret_t: list[int], q: int) -> int:
    """Return c dot tilde{t}. With zero noise, this is the plaintext."""
    return ciphertext.dot_dense(extended_secret(secret_t, q))

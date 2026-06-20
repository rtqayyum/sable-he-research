"""Sparse-LPN GSW-style matrix encryption and homomorphic evaluation."""

from __future__ import annotations

import random

from .field import sample_noise
from .params import SableParams
from .regev import extended_secret
from .sparse import SparseMatrix, SparseVector, sample_sparse_prefix


def encrypt(alpha: int, secret_s: list[int], params: SableParams, rng: random.Random) -> SparseMatrix:
    """GSW-style encryption of alpha under secret_s.

    The output matrix X satisfies X tilde{s} = alpha tilde{s} + e.
    """
    if len(secret_s) != params.n:
        raise ValueError("secret length mismatch")
    q = params.q
    rows: list[SparseVector] = []

    for j in range(params.n):
        a = sample_sparse_prefix(params.N, params.n, params.k, q, rng)
        dot_as = sum((coeff * secret_s[i]) % q for i, coeff in a.data.items()) % q
        e = sample_noise(q, params.eta, rng)
        b = (dot_as - alpha * secret_s[j] + e) % q
        data = dict(a.data)
        if b:
            data[params.n] = b
        rows.append(SparseVector(params.N, data, q))

    a = sample_sparse_prefix(params.N, params.n, params.k, q, rng)
    dot_as = sum((coeff * secret_s[i]) % q for i, coeff in a.data.items()) % q
    e = sample_noise(q, params.eta, rng)
    b = (dot_as + alpha + e) % q
    data = dict(a.data)
    if b:
        data[params.n] = b
    rows.append(SparseVector(params.N, data, q))

    return SparseMatrix(params.N, params.N, rows, q)


def message_residuals(matrix: SparseMatrix, alpha: int, secret_s: list[int]) -> list[int]:
    """Return X tilde{s} - alpha tilde{s}. Zero vector means exact encryption."""
    q = matrix.q
    ts = extended_secret(secret_s, q)
    applied = matrix.apply_to_dense(ts)
    return [(applied[i] - alpha * ts[i]) % q for i in range(matrix.nrows)]


def direct_decrypt_lastrow(matrix: SparseMatrix, secret_s: list[int]) -> int:
    """Decrypt a GSW-style ciphertext by its final row.

    With no error, the result is the encrypted scalar.
    """
    return matrix.last_row().dot_dense(extended_secret(secret_s, matrix.q))


def expand_vector(ciphertext: SparseVector, expansion_key: list[SparseMatrix]) -> SparseMatrix:
    """Expand a compact Regev-style vector into a GSW-style matrix."""
    if len(expansion_key) != ciphertext.length:
        raise ValueError("expansion key length mismatch")
    q = ciphertext.q
    first = expansion_key[0]
    acc = SparseMatrix.zero(first.nrows, first.ncols, q)
    for i, coeff in ciphertext.data.items():
        acc = acc.add_scaled(expansion_key[i], coeff)
    return acc


def eval_add(left: SparseMatrix, right: SparseMatrix) -> SparseMatrix:
    return left.add(right)


def eval_mul(left: SparseMatrix, right: SparseMatrix) -> SparseMatrix:
    return left.matmul(right)


def eval_mul_oriented(left: SparseMatrix, right: SparseMatrix) -> SparseMatrix:
    """Multiply with lower-sparsity matrix on the left when orientation is irrelevant.

    Matrix multiplication of ciphertexts is not semantically commutative at the
    noise level, but both `left*right` and `right*left` encrypt the product in
    the exact/noise-free idealization. This helper is for experiments only.
    """
    if left.max_row_support() <= right.max_row_support():
        return left.matmul(right)
    return right.matmul(left)

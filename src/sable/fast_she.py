"""Vectorized SABLE-HE somewhat-homomorphic pipeline (numpy + scipy.sparse).

Same algorithm as sable.sable (Regev input -> GSW-style expansion -> matrix
add/multiply -> last-row decryption or seeded compaction), but:

* matrices are CSR over int64 with q < 2^28, so products never overflow;
* expansion-key matrices X_i are derived lazily from (seed, i), so only the
  k+1 matrices that a ciphertext touches are ever built.  This makes
  n = 65536 and larger feasible for benchmarks.  A deployed evaluator must
  store the b-column of every X_i (N field elements each); key_sizes()
  reports that cost honestly;
* the compaction key is seeded: CLPN matrices A_i are re-derived from
  (seed, i) by whoever needs them.

This module is for measurement.  Security depends on the chosen parameters;
see sable.sparse_attacks and sable.parameter_sets.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

import numpy as np
import scipy.sparse as sp

from .field import is_prime

Q28 = 268435399  # largest prime below 2^28


def _rng(seed: Iterable[int]) -> np.random.Generator:
    return np.random.Generator(np.random.PCG64(np.random.SeedSequence(list(seed))))


@dataclass(frozen=True)
class SheParams:
    name: str
    n: int
    k: int
    q: int
    eta: float
    replicas: int = 1

    def __post_init__(self) -> None:
        if not is_prime(self.q) or self.q >= 2**28:
            raise ValueError("q must be a prime below 2^28")

    @property
    def N(self) -> int:
        return self.n + 1

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CompactParams:
    n_c: int
    m_c: int
    eta_c: float


def _distinct_positions(rng: np.random.Generator, rows: int, k: int, n: int) -> np.ndarray:
    pos = rng.integers(0, n, size=(rows, k), dtype=np.int64)
    if k > 1:
        for _ in range(64):
            srt = np.sort(pos, axis=1)
            dup = np.any(srt[:, 1:] == srt[:, :-1], axis=1)
            if not dup.any():
                break
            pos[dup] = rng.integers(0, n, size=(int(dup.sum()), k), dtype=np.int64)
    return pos


def _noise(rng: np.random.Generator, size: Any, q: int, eta: float) -> np.ndarray:
    hit = rng.random(size) < eta
    return np.where(hit, rng.integers(1, q, size=size, dtype=np.int64), 0)


def gsw_matrix(p: SheParams, s: np.ndarray, alpha: int, rng: np.random.Generator) -> sp.csr_matrix:
    """Sparse GSW-style encryption X of alpha under s: X tilde_s = alpha tilde_s + e."""
    n, N, k, q = p.n, p.N, p.k, p.q
    pos = _distinct_positions(rng, N, k, n)
    coeff = rng.integers(1, q, size=(N, k), dtype=np.int64)
    dot = np.zeros(N, dtype=np.int64)
    for j in range(k):
        dot = (dot + coeff[:, j] * s[pos[:, j]] % q) % q
    b = (dot + _noise(rng, N, q, p.eta)) % q
    b[:n] = (b[:n] - (alpha % q) * s % q) % q
    b[n] = (b[n] + alpha) % q
    indices = np.concatenate([pos, np.full((N, 1), n, dtype=np.int64)], axis=1).ravel()
    data = np.concatenate([coeff, b[:, None]], axis=1).ravel()
    indptr = np.arange(0, N * (k + 1) + 1, k + 1, dtype=np.int64)
    X = sp.csr_matrix((data, indices, indptr), shape=(N, N))
    X.eliminate_zeros()
    X.sort_indices()
    return X


@dataclass
class SheKeys:
    params: SheParams
    seed: int
    t: np.ndarray
    s: np.ndarray
    _cache: dict[int, sp.csr_matrix] = field(default_factory=dict, repr=False)

    @property
    def tilde_t(self) -> np.ndarray:
        return np.concatenate([(-self.t) % self.params.q, [1]])

    @property
    def tilde_s(self) -> np.ndarray:
        return np.concatenate([(-self.s) % self.params.q, [1]])

    def X(self, i: int) -> sp.csr_matrix:
        """Expansion-key matrix i (GSW encryption of tilde_t[i] under s), derived lazily."""
        M = self._cache.get(i)
        if M is None:
            alpha = int(self.tilde_t[i])
            M = gsw_matrix(self.params, self.s, alpha, _rng([self.seed, i, 0x65]))
            self._cache[i] = M
        return M

    def clear_cache(self) -> None:
        self._cache.clear()


def keygen(p: SheParams, seed: int) -> SheKeys:
    rng = _rng([seed, 0x5EED])
    t = rng.integers(0, p.q, size=p.n, dtype=np.int64)
    s = rng.integers(0, p.q, size=p.n, dtype=np.int64)
    return SheKeys(p, seed, t, s)


def key_sizes(p: SheParams, cp: CompactParams | None = None) -> dict[str, float]:
    """Storage (bytes) of the evaluation keys when A-parts are seed-derived."""
    qb = math.ceil(math.log2(p.q)) / 8  # packed bytes per field element
    out = {
        "expansion_key_b_columns_bytes": p.N * p.N * qb,
        "expansion_key_full_sparse_bytes": p.N * p.N * (p.k + 1) * (qb + 4),
        "fresh_ciphertext_bytes": p.replicas * (p.k * (4 + qb) + qb),
        "fresh_ciphertext_seeded_bytes": p.replicas * qb + 32,
        "expanded_ciphertext_bytes": p.replicas * p.N * (p.k + 1) ** 2 * (qb + 4),
    }
    if cp is not None:
        out["compaction_key_b_bytes"] = p.N * cp.m_c * qb
        out["compaction_key_dense_bytes"] = p.N * cp.m_c * (cp.n_c + 1) * qb
    return out


# --------------------------------------------------------------------------- ciphertexts


@dataclass(frozen=True)
class FreshCiphertext:
    cols: np.ndarray  # (R, k+1); last column is n (the b slot)
    vals: np.ndarray  # (R, k+1)


def encrypt(keys: SheKeys, mu: int, noise_seed: int) -> FreshCiphertext:
    p = keys.params
    R, k, q, n = p.replicas, p.k, p.q, p.n
    rng = _rng([noise_seed, 0xC7])
    pos = _distinct_positions(rng, R, k, n)
    coeff = rng.integers(1, q, size=(R, k), dtype=np.int64)
    dot = np.zeros(R, dtype=np.int64)
    for j in range(k):
        dot = (dot + coeff[:, j] * keys.t[pos[:, j]] % q) % q
    b = (dot + (mu % q) + _noise(rng, R, q, p.eta)) % q
    cols = np.concatenate([pos, np.full((R, 1), n, dtype=np.int64)], axis=1)
    vals = np.concatenate([coeff, b[:, None]], axis=1)
    return FreshCiphertext(cols, vals)


def expand(keys: SheKeys, ct: FreshCiphertext) -> list[sp.csr_matrix]:
    q = keys.params.q
    out = []
    for r in range(ct.cols.shape[0]):
        acc = None
        for c, v in zip(ct.cols[r].tolist(), ct.vals[r].tolist()):
            if v % q == 0:
                continue
            term = keys.X(c) * int(v)
            acc = term if acc is None else acc + term
        acc = acc if acc is not None else sp.csr_matrix((keys.params.N, keys.params.N), dtype=np.int64)
        acc.data %= q
        acc.eliminate_zeros()
        out.append(acc)
    return out


def add(A: list[sp.csr_matrix], B: list[sp.csr_matrix], q: int) -> list[sp.csr_matrix]:
    out = []
    for a, b in zip(A, B):
        c = a + b
        c.data %= q
        c.eliminate_zeros()
        out.append(c)
    return out


def _matmul_mod(a: sp.csr_matrix, b: sp.csr_matrix, q: int) -> sp.csr_matrix:
    row_nnz = int(np.diff(a.indptr).max()) if a.nnz else 0
    if row_nnz * float(q) * float(q) < 2.0**62:
        c = a @ b
        c.data %= q
    else:  # split a's entries into 14-bit halves so every partial sum fits in int64
        lo = a.copy()
        lo.data = a.data & 0x3FFF
        hi = a.copy()
        hi.data = a.data >> 14
        c_lo = lo @ b
        c_lo.data %= q
        c_hi = hi @ b
        c_hi.data %= q
        c_hi.data = (c_hi.data * (1 << 14)) % q
        c = c_hi + c_lo
        c.data %= q
    c.eliminate_zeros()
    return c


def mul(A: list[sp.csr_matrix], B: list[sp.csr_matrix], q: int) -> list[sp.csr_matrix]:
    return [_matmul_mod(a, b, q) for a, b in zip(A, B)]


def scalar_mul(A: list[sp.csr_matrix], c: int, q: int) -> list[sp.csr_matrix]:
    out = []
    for a in A:
        m = a * int(c % q)
        m.data %= q
        out.append(m)
    return out


def last_row(C: sp.csr_matrix) -> tuple[np.ndarray, np.ndarray]:
    lo, hi = C.indptr[-2], C.indptr[-1]
    return C.indices[lo:hi].astype(np.int64), C.data[lo:hi].astype(np.int64)


def decrypt_replica(keys: SheKeys, C: sp.csr_matrix) -> int:
    q = keys.params.q
    idx, val = last_row(C)
    ts = keys.tilde_s
    return int(np.sum(val * ts[idx] % q) % q)


def decrypt(keys: SheKeys, Cs: list[sp.csr_matrix]) -> tuple[int, int]:
    """Plurality over replicas.  Returns (value, votes for the winner)."""
    vals = [decrypt_replica(keys, C) for C in Cs]
    cnt = Counter(vals)
    best = max(cnt.items(), key=lambda kv: (kv[1], -kv[0]))
    return best[0], best[1]


def nnz(Cs: list[sp.csr_matrix]) -> int:
    return int(sum(C.nnz for C in Cs))


# --------------------------------------------------------------------------- seeded compaction


@dataclass
class CompactKey:
    """Seeded coordinate compaction key: CLPN encryptions of tilde_s coordinates under r."""

    she: SheKeys
    cp: CompactParams
    seed: int
    r: np.ndarray
    _b: dict[int, np.ndarray] = field(default_factory=dict, repr=False)

    def A(self, i: int) -> np.ndarray:
        q = self.she.params.q
        return _rng([self.seed, i, 0xA]).integers(0, q, size=(self.cp.m_c, self.cp.n_c), dtype=np.int64)

    def b(self, i: int) -> np.ndarray:
        v = self._b.get(i)
        if v is None:
            q = self.she.params.q
            A = self.A(i)
            Ar = (A % q) @ self.r % q if self.cp.n_c * q * q < 2**62 else _dense_dot_mod(A, self.r, q)
            e = _noise(_rng([self.seed, i, 0xE]), self.cp.m_c, q, self.cp.eta_c)
            v = (Ar + int(self.she.tilde_s[i]) + e) % q
            self._b[i] = v
        return v


def _dense_dot_mod(A: np.ndarray, r: np.ndarray, q: int) -> np.ndarray:
    acc = np.zeros(A.shape[0], dtype=np.int64)
    step = max(1, int(2**62 // (q * q)) - 1)
    for s0 in range(0, A.shape[1], step):
        acc = (acc + A[:, s0:s0 + step] @ r[s0:s0 + step]) % q
    return acc


def compact_keygen(she: SheKeys, cp: CompactParams, seed: int) -> CompactKey:
    r = _rng([seed, 0x12]).integers(0, she.params.q, size=cp.n_c, dtype=np.int64)
    return CompactKey(she, cp, seed, r)


def compact(ck: CompactKey, C: sp.csr_matrix) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Evaluator side: b_out = sum_i c_i b_i.  Output = (support, coefficients, b_out)."""
    q = ck.she.params.q
    idx, val = last_row(C)
    acc = np.zeros(ck.cp.m_c, dtype=np.int64)
    for i, c in zip(idx.tolist(), val.tolist()):
        acc = (acc + int(c) * ck.b(i)) % q
    return idx, val, acc


def decrypt_compact(ck: CompactKey, out: tuple[np.ndarray, np.ndarray, np.ndarray]) -> tuple[int, int]:
    """Decryptor side: plurality over rows of b_out - sum_i c_i A_i r."""
    q = ck.she.params.q
    idx, val, bout = out
    acc = np.zeros(ck.cp.m_c, dtype=np.int64)
    for i, c in zip(idx.tolist(), val.tolist()):
        Ar = _dense_dot_mod(ck.A(i), ck.r, q)
        acc = (acc + int(c) * Ar) % q
    resid = (bout - acc) % q
    cnt = Counter(resid.tolist())
    best = max(cnt.items(), key=lambda kv: (kv[1], -kv[0]))
    return best[0], best[1]


__all__ = [
    "CompactKey", "CompactParams", "FreshCiphertext", "Q28", "SheKeys", "SheParams",
    "add", "compact", "compact_keygen", "decrypt", "decrypt_compact", "decrypt_replica",
    "encrypt", "expand", "gsw_matrix", "key_sizes", "keygen", "last_row", "mul", "nnz", "scalar_mul",
]

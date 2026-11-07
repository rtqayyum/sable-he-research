"""Vectorized sparse-LPN Regev layer for key-additive secure aggregation.

This is the input layer of SABLE-HE (Regev-style ciphertexts under sparse
q-ary LPN) used in a key-additive mode, which is the natural fit for
federated aggregation:

* Each round has a public seed.  Everyone derives the same sparse vectors
  a_{j,r} (k nonzeros out of n) for every coordinate j and replica r.
* Client c holds a fresh secret t_c and uploads only
  b_c[j, r] = <a_{j,r}, t_c> + m_c[j] + e_c[j, r]   (mod q).
* The server adds the uploads.  The sum decrypts with T = sum_c t_c, which
  a key authority (a committee, or one trusted process in the simulation)
  holds.  The server forwards the aggregate to the key authority and gets back
  only the decoded sum.  The server must never hold T: with T and the
  individual uploads it can recover every client key (sable.keysum_attack).
* Decryption computes B - <a, T> and takes the plurality over the R
  replicas, which absorbs the accumulated sparse noise.

Upload size is R * ceil(log2 q) bits per scalar because the a vectors come
from the public seed.  Everything is numpy-vectorized and chunked, so model
sizes of 10^5 parameters run in seconds.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Iterable

import numpy as np

from .field import is_prime
from .sparse_attacks import plurality_failure_bound, sparse_layer_screen

CHUNK = 8192


@dataclass(frozen=True)
class RegevAggParams:
    name: str
    n: int
    k: int
    q: int
    eta: float
    replicas: int

    def __post_init__(self) -> None:
        if not is_prime(self.q):
            raise ValueError("q must be prime")
        if self.q >= 2**31:
            raise ValueError("q must be below 2^31 for int64 arithmetic")
        if not (1 <= self.k <= self.n):
            raise ValueError("need 1 <= k <= n")
        if self.replicas < 1:
            raise ValueError("replicas must be positive")

    @property
    def coeff_bits(self) -> int:
        return math.ceil(math.log2(self.q))

    def upload_bytes(self, d: int) -> int:
        """Bytes a client uploads for d scalars (b values only; a is seed-derived)."""
        return math.ceil(d * self.replicas * self.coeff_bits / 8)

    def unseeded_upload_bytes(self, d: int) -> int:
        """Bytes if the sparse a vectors were sent explicitly (index + coefficient)."""
        idx_bits = math.ceil(math.log2(self.n))
        per = self.coeff_bits + self.k * (idx_bits + self.coeff_bits)
        return math.ceil(d * self.replicas * per / 8)

    def p_replica_correct(self, clients: int) -> float:
        """Probability that one replica of a K-client sum has zero noise."""
        return (1.0 - self.eta) ** clients

    def failure_bound(self, clients: int) -> float:
        """Upper bound on the per-coordinate decoding failure for a K-client sum."""
        return plurality_failure_bound(self.replicas, self.p_replica_correct(clients), self.q)

    def security_screen(self, samples_per_key: int, target_bits: int = 128) -> dict[str, Any]:
        """Sparse-LPN screen for one client key (no expansion key is published)."""
        scr = sparse_layer_screen(self.n, self.k, self.eta, self.q, samples_per_key, target_bits=target_bits, expansion_key_exposed=False)
        return scr.to_jsonable()

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def choose_replicas(n: int, k: int, q: int, eta: float, clients: int, target_failure: float = 1e-12, max_replicas: int = 4001) -> int:
    """Smallest odd replica count R whose plurality bound for a K-client sum is <= target_failure.

    The noise of K summed uploads makes one replica correct with probability
    (1-eta)^K, so R must grow with the number of clients.
    """
    R = 3
    while R <= max_replicas:
        if RegevAggParams("tmp", n=n, k=k, q=q, eta=eta, replicas=R).failure_bound(clients) <= target_failure:
            return R
        R += 2
    raise ValueError(f"no replica count up to {max_replicas} reaches {target_failure:g} for K={clients}, eta={eta}")


def params_for_clients(n: int, eta: float, clients: int, *, k: int = 5, q: int = 2147483647,
                       target_failure: float = 1e-12) -> RegevAggParams:
    R = choose_replicas(n, k, q, eta, clients, target_failure)
    return RegevAggParams(f"fl_k{k}_n{n}_eta{eta:g}_K{clients}_R{R}", n=n, k=k, q=q, eta=eta, replicas=R)


# Default parameter rows for the FL case study (review targets, not certified).
FL_PARAMS: dict[str, RegevAggParams] = {
    "fl_k5_n65536_r25": RegevAggParams("fl_k5_n65536_r25", n=65536, k=5, q=2147483647, eta=0.003, replicas=25),
    "fl_k5_n65536_r51": RegevAggParams("fl_k5_n65536_r51", n=65536, k=5, q=2147483647, eta=0.003, replicas=51),
    "fl_k4_n65536_r25": RegevAggParams("fl_k4_n65536_r25", n=65536, k=4, q=2147483647, eta=0.003, replicas=25),
    "fl_k5_n131072_r25": RegevAggParams("fl_k5_n131072_r25", n=131072, k=5, q=2147483647, eta=0.0015, replicas=25),
    "fl_toy_n1024_r9": RegevAggParams("fl_toy_n1024_r9", n=1024, k=5, q=2147483647, eta=0.003, replicas=9),
}


def _rng(seed: Iterable[int] | int) -> np.random.Generator:
    if isinstance(seed, int):
        seed = [seed]
    return np.random.Generator(np.random.PCG64(np.random.SeedSequence(list(seed))))


def public_sparse_vectors(params: RegevAggParams, round_seed: int, start: int, stop: int) -> tuple[np.ndarray, np.ndarray]:
    """Derive the public sparse vectors for coordinates [start, stop).

    Returns (idx, coeff) with shape (stop-start, R, k).  Positions within a
    vector are distinct.  The chunk is derived from (round_seed, start) so any
    party can regenerate any chunk independently.
    """
    d = stop - start
    R, k, n, q = params.replicas, params.k, params.n, params.q
    rng = _rng([round_seed, start, 0x5AB1E])
    idx = rng.integers(0, n, size=(d, R, k), dtype=np.int64)
    if k > 1:
        for _ in range(64):
            srt = np.sort(idx, axis=2)
            dup = np.any(srt[:, :, 1:] == srt[:, :, :-1], axis=2)
            if not dup.any():
                break
            where = np.nonzero(dup)
            idx[where] = rng.integers(0, n, size=(len(where[0]), k), dtype=np.int64)
    coeff = rng.integers(1, q, size=(d, R, k), dtype=np.int64)
    return idx, coeff


def keygen(params: RegevAggParams, seed: int) -> np.ndarray:
    return _rng([seed, 0x7EC]).integers(0, params.q, size=params.n, dtype=np.int64)


def _dot(idx: np.ndarray, coeff: np.ndarray, t: np.ndarray, q: int) -> np.ndarray:
    acc = np.zeros(idx.shape[:2], dtype=np.int64)
    for j in range(idx.shape[2]):
        acc = (acc + (coeff[:, :, j] * t[idx[:, :, j]]) % q) % q
    return acc


def encrypt(params: RegevAggParams, t: np.ndarray, m: np.ndarray, round_seed: int, noise_seed: int) -> np.ndarray:
    """Encrypt the encoded vector m (int64, values mod q) under client key t.

    Returns b with shape (d, R).
    """
    m = np.asarray(m, dtype=np.int64) % params.q
    d = m.shape[0]
    q, R = params.q, params.replicas
    out = np.empty((d, R), dtype=np.int64)
    rng = _rng([noise_seed, 0xE77])
    for start in range(0, d, CHUNK):
        stop = min(d, start + CHUNK)
        idx, coeff = public_sparse_vectors(params, round_seed, start, stop)
        dot = _dot(idx, coeff, t, q)
        noisy = rng.random((stop - start, R)) < params.eta
        e = np.where(noisy, rng.integers(1, q, size=(stop - start, R), dtype=np.int64), 0)
        out[start:stop] = (dot + m[start:stop, None] + e) % q
    return out


def aggregate(uploads: Iterable[np.ndarray], q: int) -> np.ndarray:
    acc = None
    for b in uploads:
        acc = b.copy() if acc is None else (acc + b) % q
    if acc is None:
        raise ValueError("no uploads")
    return acc


def plurality(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Row-wise plurality.  Returns (winner, winner_count, runner_up_count)."""
    d, R = values.shape
    s = np.sort(values, axis=1)
    change = np.ones_like(s, dtype=bool)
    change[:, 1:] = s[:, 1:] != s[:, :-1]
    run = np.cumsum(change, axis=1) - 1  # 0-based run id
    flat = run + (np.arange(d)[:, None] * R)
    counts = np.bincount(flat.ravel(), minlength=d * R).reshape(d, R)
    best = counts.argmax(axis=1)
    best_count = counts[np.arange(d), best]
    pos = (run == best[:, None]).argmax(axis=1)
    winner = s[np.arange(d), pos]
    c2 = counts.copy()
    c2[np.arange(d), best] = -1
    second = c2.max(axis=1)
    return winner, best_count, np.maximum(second, 0)


def decrypt_sum(params: RegevAggParams, T: np.ndarray, B: np.ndarray, round_seed: int) -> dict[str, np.ndarray]:
    """Decrypt an aggregated upload B with the summed key T.

    Returns {"value": field values (d,), "votes": winner counts, "runner_up": second counts}.
    """
    q = params.q
    d = B.shape[0]
    value = np.empty(d, dtype=np.int64)
    votes = np.empty(d, dtype=np.int64)
    runner = np.empty(d, dtype=np.int64)
    for start in range(0, d, CHUNK):
        stop = min(d, start + CHUNK)
        idx, coeff = public_sparse_vectors(params, round_seed, start, stop)
        resid = (B[start:stop] - _dot(idx, coeff, T, q)) % q
        w, c1, c2 = plurality(resid)
        value[start:stop], votes[start:stop], runner[start:stop] = w, c1, c2
    return {"value": value, "votes": votes, "runner_up": runner}


def to_signed(values: np.ndarray, q: int) -> np.ndarray:
    v = np.asarray(values, dtype=np.int64) % q
    return np.where(v > q // 2, v - q, v)


@dataclass(frozen=True)
class FixedPoint:
    """Fixed-point encoder with an explicit overflow check for K-client sums."""

    q: int
    scale: int
    clip: float

    def check_capacity(self) -> None:
        if self.clip * self.scale >= self.q // 2:
            raise ValueError("clip*scale must stay below q/2 so the weighted sum cannot wrap")

    def encode(self, x: np.ndarray, weight: float = 1.0) -> np.ndarray:
        self.check_capacity()
        v = np.clip(np.asarray(x, dtype=np.float64), -self.clip, self.clip) * weight
        return np.rint(v * self.scale).astype(np.int64) % self.q

    def decode(self, v: np.ndarray) -> np.ndarray:
        return to_signed(v, self.q).astype(np.float64) / self.scale


__all__ = [
    "FL_PARAMS",
    "FixedPoint",
    "RegevAggParams",
    "aggregate",
    "choose_replicas",
    "decrypt_sum",
    "encrypt",
    "keygen",
    "params_for_clients",
    "plurality",
    "public_sparse_vectors",
    "to_signed",
]

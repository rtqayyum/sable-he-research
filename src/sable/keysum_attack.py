"""Key-sum attack on key-additive sparse-LPN aggregation.

Setting (fast_regev key-additive mode): client c uploads
    b_c[j, r] = <a_{j,r}, t_c> + m_c[j] + e_c[j, r]   (mod q)
for every coordinate j and replica r.  The noise e_c is zero with probability
1 - eta and uniform in [1, q-1] otherwise.

If the party that sees the individual uploads also learns the summed key
T = sum_c t_c, it can decode the sum M[j] and compute the aggregate residual
    E[j, r] = sum_c b_c[j, r] - <a_{j,r}, T> - M[j] = sum_c e_c[j, r].
Where E[j, r] = 0, every client's noise is zero, except with probability
about (K eta)^2 / q.  For q close to 2^31 this is negligible, so these
positions give exact equations

    b_c[j, r] - b_c[j, r0] = <a_{j,r} - a_{j,r0}, t_c>

for two clean replicas r, r0 of one coordinate.  About d (R (1-eta)^K - 1)
such equations appear per client per round.  Once they exceed n, Gaussian
elimination recovers t_c and then every individual update m_c.

Hamming-metric noise is the reason: a sum of LPN errors is zero only when
(almost) every term is zero, while a sum of Gaussian LWE errors hides its
terms.  Bitzer et al. (arXiv 2601.13031) show that key-sum leakage reduces
LPN security to a noise rate of about eta^2 / (q - 1); for large q that rate
is effectively zero, which this attack makes concrete.

Countermeasure used by SABLE-HE: the aggregation server never learns T.  It
forwards the aggregate B to a key authority (committee or HSM) that returns
only M.  The server and the key authority must not collude.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from .fast_regev import CHUNK, RegevAggParams, _dot, public_sparse_vectors
from .sparse_attacks import solve_mod


def _vectors(params: RegevAggParams, round_seed: int, d: int) -> tuple[np.ndarray, np.ndarray]:
    idx, co = [], []
    for s in range(0, d, CHUNK):
        i, c = public_sparse_vectors(params, round_seed, s, min(d, s + CHUNK))
        idx.append(i)
        co.append(c)
    return np.concatenate(idx), np.concatenate(co)


def clean_mask(params: RegevAggParams, T: np.ndarray, B: np.ndarray, M: np.ndarray, round_seed: int) -> np.ndarray:
    """Positions (j, r) where the aggregate noise is zero, as seen by a party holding T."""
    idx, co = _vectors(params, round_seed, B.shape[0])
    resid = (B - _dot(idx, co, T, params.q) - (np.asarray(M, dtype=np.int64) % params.q)[:, None]) % params.q
    return resid == 0


def key_sum_equations(params: RegevAggParams, b: np.ndarray, clean: np.ndarray, round_seed: int
                      ) -> tuple[list[np.ndarray], list[np.ndarray], list[int]]:
    """Exact linear equations in one client's key from clean replica pairs.

    Returns (columns, coefficients, right-hand sides); each row has at most 2k nonzeros.
    """
    q = params.q
    idx, co = _vectors(params, round_seed, b.shape[0])
    cols: list[np.ndarray] = []
    vals: list[np.ndarray] = []
    rhs: list[int] = []
    for j in range(b.shape[0]):
        cr = np.flatnonzero(clean[j])
        if cr.size < 2:
            continue
        r0 = int(cr[0])
        for r in cr[1:]:
            cols.append(np.concatenate([idx[j, r], idx[j, r0]]))
            vals.append(np.concatenate([co[j, r], (q - co[j, r0]) % q]))
            rhs.append(int((b[j, r] - b[j, r0]) % q))
    return cols, vals, rhs


def recover_key(params: RegevAggParams, b: np.ndarray, clean: np.ndarray, round_seed: int) -> np.ndarray | None:
    """Recover a client's key by dense Gaussian elimination (small n only; returns None if rank deficient)."""
    cols, vals, rhs = key_sum_equations(params, b, clean, round_seed)
    n, q = params.n, params.q
    if len(rhs) < n:
        return None
    A = np.zeros((len(rhs), n), dtype=np.int64)
    for i, (c, v) in enumerate(zip(cols, vals)):
        for cc, vv in zip(c, v):
            A[i, cc] = (A[i, cc] + vv) % q
    return solve_mod(A, np.asarray(rhs, dtype=np.int64), q)


def expected_equations(params: RegevAggParams, d: int, clients: int) -> float:
    """Expected exact equations per client per round when the server knows T."""
    p = params.p_replica_correct(clients)
    R = params.replicas
    # E[max(C - 1, 0)] for C ~ Binomial(R, p)
    return d * (R * p - 1 + (1 - p) ** R)


def key_sum_exposure(params: RegevAggParams, d: int, clients: int) -> dict[str, Any]:
    """Analytic screen: rounds until a server that knows T can solve for each client key."""
    eq = expected_equations(params, d, clients)
    rounds = math.inf if eq <= 0 else math.ceil(1.05 * params.n / eq)
    return {
        "equations_per_round": eq,
        "equations_over_n": eq / params.n,
        "rounds_to_recover_key": rounds,
        "verdict": "broken-if-server-learns-key-sum" if math.isfinite(rounds) else "no-equations",
        "residual_noise_rate": (clients * params.eta) ** 2 / params.q,
    }


__all__ = ["clean_mask", "expected_equations", "key_sum_equations", "key_sum_exposure", "recover_key"]

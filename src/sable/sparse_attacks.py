"""Sparse-LPN-specific attack screens and executable attacks.

The dense ISD/BKW screens elsewhere in this package treat the sparse layer as
if it were ordinary LPN.  That misses attacks that exploit sparsity or the
structure of the public expansion key.  This module adds three screens and
executable versions of the two attacks that are cheap to run:

1. Known-plaintext expansion-key attack.  The expansion key contains a
   GSW-style encryption X_n of the known value 1 (the last coordinate of
   tilde_t).  So (X_n - I) tilde_s = e is a linear system in s with n+1
   equations.  If e = 0, one Gaussian elimination recovers s.  The success
   probability per attempt is (1 - eta)^(n+1).

2. Low-sparsity propagation.  For k = 1 each sample isolates one secret
   coordinate.  For k = 2 the samples form a noisy two-variable linear system
   over F_q.  On the random graph formed by the samples, a breadth-first
   expansion from one root expresses every coordinate as an affine function
   of the root.  Non-tree edges then vote for the root value and local
   plurality voting removes the remaining path errors.  This runs in
   near-linear time.

3. Sample-count threshold.  A common rule of thumb for k-sparse LPN is that
   polynomial-time attacks appear once the number of public samples m
   reaches roughly n^(k/2).  The screen reports the margin k/2 - log_n(m).

These screens are conservative indicators, not proofs of security.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Sequence

# ---------------------------------------------------------------------------
# Screens (analytic)
# ---------------------------------------------------------------------------


def _neg_log2_one_minus(p: float) -> float:
    if p <= 0:
        return 0.0
    if p >= 1:
        return float("inf")
    return -math.log2(1.0 - p)


def known_plaintext_gsw_bits(n: int, eta: float) -> float:
    """Work (bits) of the clean-system attack on the expansion-key matrix X_n.

    One attempt costs about n^3 field operations and succeeds with
    probability (1-eta)^(n+1).  With eta = 0 the attack is deterministic.
    The estimate assumes the attacker can obtain fresh attempts (for example
    from powers of X_n or from information-set selection), which is
    conservative for the defender.
    """
    work = 3.0 * math.log2(max(2, n))
    return work + (n + 1) * _neg_log2_one_minus(eta)


def low_sparsity_bits(n: int, k: int, samples: int, q: int) -> float | None:
    """Work (bits) of propagation attacks for k <= 2, or None if not applicable."""
    if k <= 0:
        return 0.0
    if k == 1:
        # each sample a_i s_i + e reveals s_i up to noise; plurality over repeats
        return math.log2(max(2, samples)) + math.log2(max(2, math.log2(q)))
    if k == 2:
        # BFS + voting is near-linear when the sample graph has a giant
        # component (samples > n/2) and enough cycles (samples >= ~2n).
        if samples >= 2 * n:
            return math.log2(max(2, samples)) + 2 * math.log2(max(2, math.log2(q)))
        return None
    return None


def sample_threshold_margin(n: int, k: int, samples: int) -> float:
    """Return k/2 - log_n(samples).  Non-positive means m >= n^(k/2)."""
    if samples <= 1 or n <= 1:
        return float(k) / 2.0
    return k / 2.0 - math.log(samples) / math.log(n)


@dataclass(frozen=True)
class SparseLayerScreen:
    n: int
    k: int
    eta: float
    q: int
    samples: int
    target_bits: int
    clean_subset_bits: float
    known_plaintext_gsw_bits: float | None
    low_sparsity_bits: float | None
    sample_threshold_margin: float
    min_bits: float
    verdict: str
    blockers: tuple[str, ...] = field(default_factory=tuple)

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["blockers"] = list(self.blockers)
        for key, value in list(d.items()):
            if isinstance(value, float) and math.isinf(value):
                d[key] = "inf"
        return d


def sparse_layer_screen(
    n: int,
    k: int,
    eta: float,
    q: int,
    samples: int,
    *,
    target_bits: int = 128,
    expansion_key_exposed: bool = True,
) -> SparseLayerScreen:
    """Screen one sparse-LPN surface (dimension n, sparsity k, noise eta)."""
    clean = n * _neg_log2_one_minus(eta)
    kp = known_plaintext_gsw_bits(n, eta) if expansion_key_exposed else None
    low = low_sparsity_bits(n, k, samples, q)
    margin = sample_threshold_margin(n, k, samples)
    candidates = [clean] + [x for x in (kp, low) if x is not None]
    min_bits = min(candidates)
    blockers: list[str] = []
    if eta <= 0:
        blockers.append("noise-free: the sparse layer is a plain linear system and offers no security")
    if k <= 2:
        blockers.append(f"k={k}: sparse LPN with k<=2 is solved by propagation (sable.sparse_attacks.solve_two_sparse_lpn)")
    if kp is not None and kp < target_bits:
        blockers.append("expansion-key matrix encrypting 1 is a known-plaintext linear system with few noisy rows")
    if margin <= 0:
        blockers.append("public samples m >= n^(k/2): inside the known polynomial-time regime for k-sparse LPN")
    elif margin < 0.5:
        blockers.append(f"thin sparse-LPN sample margin: k/2 - log_n(m) = {margin:.2f}")
    if min_bits < target_bits:
        blockers.append(f"minimum sparse-specific screen {min_bits:.1f} bits is below the {target_bits}-bit target")
    hard = [b for b in blockers if not b.startswith("thin")]
    verdict = "broken-or-below-target" if hard else ("thin-margin" if blockers else "passes-sparse-screens")
    return SparseLayerScreen(
        n=n, k=k, eta=eta, q=q, samples=samples, target_bits=target_bits,
        clean_subset_bits=clean, known_plaintext_gsw_bits=kp, low_sparsity_bits=low,
        sample_threshold_margin=margin, min_bits=min_bits, verdict=verdict,
        blockers=tuple(blockers),
    )


def screen_params(params: Any, *, target_bits: int = 128, extra_samples: int = 0) -> SparseLayerScreen:
    """Screen a SableParams-like object (fields n, k, eta, q) with its expansion key exposed."""
    N = params.n + 1
    return sparse_layer_screen(params.n, params.k, params.eta, params.q, N * N + extra_samples, target_bits=target_bits)


# ---------------------------------------------------------------------------
# Correctness bound for q-ary plurality decoding
# ---------------------------------------------------------------------------


def _log_binom_tail_upper(R: int, p: float, t: int) -> float:
    """log P[Bin(R,p) >= t] (Chernoff/KL bound); returns -inf when impossible."""
    if t <= 0:
        return 0.0
    if t > R or p <= 0:
        return float("-inf")
    a = t / R
    if a <= p:
        return 0.0
    if a >= 1:
        return R * math.log(p)
    return -R * (a * math.log(a / p) + (1 - a) * math.log((1 - a) / (1 - p)))


def plurality_failure_bound(R: int, p_correct: float, q: int) -> float:
    """Upper bound on the failure of plurality decoding over F_q.

    Each of R independent votes equals the correct value with probability
    p_correct and is otherwise uniform over the q-1 wrong values.  Decoding
    fails only if the correct count is at most t or some wrong value reaches
    t+1, for t = floor(p_correct * R / 2).
    """
    if p_correct <= 0:
        return 1.0
    if p_correct >= 1:
        return 0.0
    mu = p_correct * R
    t = int(mu // 2)
    if t < 1:
        return 1.0
    a = t / R  # P[C <= t] <= exp(-R * KL(a || p)) for a < p
    p = p_correct
    kl = (a * math.log(a / p) if a > 0 else 0.0) + (1 - a) * math.log((1 - a) / (1 - p))
    lower = math.exp(-R * kl)
    p_wrong = (1 - p_correct) / (q - 1)
    log_wrong = math.log(q - 1) + _log_binom_tail_upper(R, p_wrong, t + 1)
    wrong = math.exp(log_wrong) if log_wrong > -700 else 0.0
    return min(1.0, lower + wrong)


# ---------------------------------------------------------------------------
# Executable attacks
# ---------------------------------------------------------------------------


def solve_mod(A: Any, b: Any, q: int) -> Any:
    """Solve A x = b over F_q with Gaussian elimination (numpy, q < 2^31).

    Returns the unique solution, or None when the system is rank deficient
    or inconsistent (an inconsistent system means some equation is noisy).
    """
    import numpy as np

    A = np.asarray(A, dtype=np.int64) % q
    b = np.asarray(b, dtype=np.int64).reshape(-1) % q
    m, n = A.shape
    M = np.concatenate([A, b.reshape(-1, 1)], axis=1)
    row = 0
    pivots: list[int] = []
    for col in range(n):
        if row >= m:
            break
        nz = np.flatnonzero(M[row:, col])
        if nz.size == 0:
            continue
        p = row + int(nz[0])
        if p != row:
            M[[row, p]] = M[[p, row]]
        inv = pow(int(M[row, col]), q - 2, q)
        M[row] = (M[row] * inv) % q
        f = M[:, col].copy()
        f[row] = 0
        nzr = np.flatnonzero(f)
        if nzr.size:
            M[nzr] = (M[nzr] - (f[nzr, None] * M[row][None, :]) % q) % q
        pivots.append(col)
        row += 1
    if len(pivots) < n:
        return None
    if np.any(M[row:, n] % q):
        return None
    x = np.zeros(n, dtype=np.int64)
    for r, c in enumerate(pivots):
        x[c] = M[r, n]
    return x


def known_plaintext_system(rows: Sequence[dict[int, int]], n: int, q: int) -> tuple[Any, Any]:
    """Build (A, b) from the sparse rows of X_n (a GSW encryption of 1).

    Row j of (X_n - I) applied to tilde_s = (-s, 1) is zero up to noise, so
    A s = b with A = (X_n - I)[:, :n] and b = (X_n - I)[:, n].
    """
    import numpy as np

    N = n + 1
    A = np.zeros((N, n), dtype=np.int64)
    b = np.zeros(N, dtype=np.int64)
    for j, data in enumerate(rows):
        for col, val in data.items():
            if col < n:
                A[j, col] = val % q
            else:
                b[j] = val % q
        if j < n:
            A[j, j] = (A[j, j] - 1) % q
        else:
            b[j] = (b[j] - 1) % q
    return A, b


def recover_s_known_plaintext(rows: Sequence[dict[int, int]], n: int, q: int) -> Any:
    """Recover the evaluation secret s from X_n by one linear solve (None on failure)."""
    A, b = known_plaintext_system(rows, n, q)
    return solve_mod(A, b, q)


def generate_two_sparse_instance(n: int, m: int, q: int, eta: float, seed: int = 0) -> dict[str, Any]:
    """Generate m samples of 2-sparse q-ary LPN with q-ary symmetric noise rate eta."""
    import numpy as np

    rng = np.random.default_rng(seed)
    s = rng.integers(0, q, n, dtype=np.int64)
    I = rng.integers(0, n, m, dtype=np.int64)
    J = rng.integers(0, n - 1, m, dtype=np.int64)
    J = np.where(J >= I, J + 1, J)
    ai = rng.integers(1, q, m, dtype=np.int64)
    aj = rng.integers(1, q, m, dtype=np.int64)
    e = np.where(rng.random(m) < eta, rng.integers(1, q, m, dtype=np.int64), 0)
    b = (ai * s[I] % q + aj * s[J] % q + e) % q
    return {"s": s, "I": I, "J": J, "ai": ai, "aj": aj, "b": b, "n": n, "q": q, "m": m, "eta": eta}


def solve_two_sparse_lpn(
    I: Any, J: Any, ai: Any, aj: Any, b: Any, n: int, q: int,
    *, vote_stride: int = 7, rounds: int = 3, root: int = 0,
) -> dict[str, Any]:
    """Recover the secret of 2-sparse q-ary LPN by BFS propagation and voting.

    Returns {"s": estimate (numpy int64), "reached": coordinates connected to the root,
    "root_votes": votes for the winning root value}.
    """
    import numpy as np

    I = np.asarray(I, dtype=np.int64)
    J = np.asarray(J, dtype=np.int64)
    ai = np.asarray(ai, dtype=np.int64) % q
    aj = np.asarray(aj, dtype=np.int64) % q
    b = np.asarray(b, dtype=np.int64) % q
    m = len(b)
    inv_cache: dict[int, int] = {}

    def inv(x: int) -> int:
        x %= q
        r = inv_cache.get(x)
        if r is None:
            r = pow(x, q - 2, q)
            inv_cache[x] = r
        return r

    # adjacency in CSR form
    ends = np.concatenate([I, J])
    edge_ids = np.concatenate([np.arange(m), np.arange(m)])
    order = np.argsort(ends, kind="stable")
    ends_sorted = ends[order]
    adj_edges = edge_ids[order]
    starts = np.searchsorted(ends_sorted, np.arange(n + 1))

    Il, Jl, ail, ajl, bl = I.tolist(), J.tolist(), ai.tolist(), aj.tolist(), b.tolist()
    adj = adj_edges.tolist()
    st = starts.tolist()

    alpha: list[int | None] = [None] * n
    beta: list[int] = [0] * n
    alpha[root] = 1
    tree = bytearray(m)
    dq = deque([root])
    while dq:
        u = dq.popleft()
        for pos in range(st[u], st[u + 1]):
            idx = adj[pos]
            if Il[idx] == u:
                v, au, av = Jl[idx], ail[idx], ajl[idx]
            else:
                v, au, av = Il[idx], ajl[idx], ail[idx]
            if alpha[v] is None:
                iv = inv(av)
                alpha[v] = (-au * alpha[u] * iv) % q  # type: ignore[operator]
                beta[v] = ((bl[idx] - au * beta[u]) * iv) % q
                tree[idx] = 1
                dq.append(v)
    reached = sum(1 for a in alpha if a is not None)

    votes: Counter[int] = Counter()
    for idx in range(0, m, max(1, vote_stride)):
        if tree[idx]:
            continue
        i, j = Il[idx], Jl[idx]
        a_i, a_j = alpha[i], alpha[j]
        if a_i is None or a_j is None:
            continue
        c = (ail[idx] * a_i + ajl[idx] * a_j) % q
        if c:
            votes[((bl[idx] - ail[idx] * beta[i] - ajl[idx] * beta[j]) * inv(c)) % q] += 1
    if votes:
        x, top = votes.most_common(1)[0]
    else:
        x, top = 0, 0
    s_hat = [((a * x + bb) % q) if a is not None else 0 for a, bb in zip(alpha, beta)]

    for _ in range(max(0, rounds)):
        new = list(s_hat)
        for v in range(n):
            c: Counter[int] = Counter()
            for pos in range(st[v], st[v + 1]):
                idx = adj[pos]
                if Il[idx] == v:
                    u, au, av = Jl[idx], ajl[idx], ail[idx]
                else:
                    u, au, av = Il[idx], ail[idx], ajl[idx]
                c[((bl[idx] - au * s_hat[u]) * inv(av)) % q] += 1
            if c:
                new[v] = c.most_common(1)[0][0]
        s_hat = new
    return {"s": np.asarray(s_hat, dtype=np.int64), "reached": reached, "root_votes": top}


__all__ = [
    "SparseLayerScreen",
    "generate_two_sparse_instance",
    "known_plaintext_gsw_bits",
    "known_plaintext_system",
    "low_sparsity_bits",
    "plurality_failure_bound",
    "recover_s_known_plaintext",
    "sample_threshold_margin",
    "screen_params",
    "solve_mod",
    "solve_two_sparse_lpn",
    "sparse_layer_screen",
]

"""C2 q-ary code/LPN compaction layer for SABLE-HE.

This module implements the experimental SABLE-HE-C2 compactor.  The layer
replaces the v1 repetition-code CLPN compactor with a Reed-Solomon style
q-ary linear code and optional CRT residue channels.

The construction remains a research prototype, not production cryptography.
It is designed to validate algebraic correctness and parameter tradeoffs.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from functools import reduce
from operator import mul

from .field import dot_dense, is_prime, qary_piling_up, sample_noise
from .params import SableParams
from .sparse import SparseVector


class DecodeFailure(ValueError):
    """Raised when Reed-Solomon decoding cannot recover a valid message."""


@dataclass(frozen=True)
class C2ChannelCiphertext:
    """One q-ary code/LPN ciphertext channel over F_p.

    It encrypts a message vector x in F_p^ell through

        b = A r + RS(x) + e.

    Only x[0] is used as the scalar payload.  The remaining ell-1 symbols are
    one-time random mask coordinates.  Homomorphic linear evaluation preserves
    the first coordinate while aggregating the mask coordinates harmlessly.
    """

    modulus: int
    A: list[list[int]]
    b: list[int]
    code_dim: int

    def __post_init__(self) -> None:
        p = self.modulus
        if not is_prime(p):
            raise ValueError("channel modulus must be prime")
        if self.code_dim <= 0:
            raise ValueError("code_dim must be positive")
        if not self.A:
            raise ValueError("A cannot be empty")
        if len(self.A) != len(self.b):
            raise ValueError("row count mismatch")
        if len(self.A) <= self.code_dim:
            raise ValueError("code length must exceed code dimension")
        if len(self.A) >= p:
            raise ValueError("Reed-Solomon toy decoder needs code length < modulus")
        ncols = len(self.A[0])
        for row in self.A:
            if len(row) != ncols:
                raise ValueError("A rows must have equal length")
        object.__setattr__(self, "A", [[x % p for x in row] for row in self.A])
        object.__setattr__(self, "b", [x % p for x in self.b])

    @property
    def m(self) -> int:
        return len(self.b)

    @property
    def n(self) -> int:
        return len(self.A[0])

    @classmethod
    def zero(cls, modulus: int, m: int, n: int, code_dim: int) -> "C2ChannelCiphertext":
        return cls(modulus, [[0] * n for _ in range(m)], [0] * m, code_dim)

    def add_scaled(self, other: "C2ChannelCiphertext", alpha: int) -> "C2ChannelCiphertext":
        if (
            self.modulus != other.modulus
            or self.m != other.m
            or self.n != other.n
            or self.code_dim != other.code_dim
        ):
            raise ValueError("incompatible C2 channel ciphertexts")
        p = self.modulus
        a = alpha % p
        if a == 0:
            return self
        A = []
        for row_self, row_other in zip(self.A, other.A):
            A.append([(x + a * y) % p for x, y in zip(row_self, row_other)])
        b = [(x + a * y) % p for x, y in zip(self.b, other.b)]
        return C2ChannelCiphertext(p, A, b, self.code_dim)


@dataclass(frozen=True)
class C2Ciphertext:
    """Multi-channel C2 ciphertext.

    If `moduli` is a singleton equal to the SABLE plaintext modulus q, the
    ciphertext decrypts directly in F_q.  If several CRT moduli are used, the
    decoder reconstructs the integer linear form modulo their product and then
    reduces modulo q.  Correct CRT mode therefore requires a product large
    enough for the intended integer representative bound, or inclusion of q as
    one of the channels.
    """

    q: int
    channels: tuple[C2ChannelCiphertext, ...]

    def __post_init__(self) -> None:
        if not self.channels:
            raise ValueError("C2 ciphertext needs at least one channel")
        m = self.channels[0].m
        n = self.channels[0].n
        ell = self.channels[0].code_dim
        for ch in self.channels:
            if ch.m != m or ch.n != n or ch.code_dim != ell:
                raise ValueError("all C2 channels must have matching shape")

    @property
    def moduli(self) -> tuple[int, ...]:
        return tuple(ch.modulus for ch in self.channels)

    @property
    def m(self) -> int:
        return self.channels[0].m

    @property
    def n(self) -> int:
        return self.channels[0].n

# ---------------------------------------------------------------------------
# Finite-field helpers and Reed-Solomon coding


def inv_mod(x: int, p: int) -> int:
    x %= p
    if x == 0:
        raise ZeroDivisionError("zero has no inverse")
    return pow(x, p - 2, p)


def _trim(poly: list[int]) -> list[int]:
    out = poly[:]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def poly_eval(poly: list[int], x: int, p: int) -> int:
    acc = 0
    # Horner from high to low.
    for coeff in reversed(poly):
        acc = (acc * x + coeff) % p
    return acc


def poly_divmod(num: list[int], den: list[int], p: int) -> tuple[list[int], list[int]]:
    num = _trim([x % p for x in num])
    den = _trim([x % p for x in den])
    if len(den) == 1 and den[0] == 0:
        raise ZeroDivisionError("polynomial division by zero")
    if len(num) < len(den):
        return [0], num
    q = [0] * (len(num) - len(den) + 1)
    rem = num[:]
    inv_lead = inv_mod(den[-1], p)
    while len(rem) >= len(den) and not (len(rem) == 1 and rem[0] == 0):
        factor = rem[-1] * inv_lead % p
        shift = len(rem) - len(den)
        q[shift] = factor
        for i, coeff in enumerate(den):
            rem[shift + i] = (rem[shift + i] - factor * coeff) % p
        rem = _trim(rem)
    return _trim(q), _trim(rem)


def rs_points(modulus: int, length: int) -> list[int]:
    if length >= modulus:
        raise ValueError("RS length must be less than modulus in this prototype")
    return list(range(1, length + 1))


def rs_encode(message: list[int], modulus: int, length: int) -> list[int]:
    if len(message) >= length:
        raise ValueError("message dimension must be smaller than code length")
    pts = rs_points(modulus, length)
    msg = [x % modulus for x in message]
    return [poly_eval(msg, x, modulus) for x in pts]


def solve_linear_modp(matrix: list[list[int]], rhs: list[int], p: int) -> list[int]:
    """Solve an overdetermined linear system over F_p.

    Returns one solution with free variables set to zero.  Raises DecodeFailure
    when the system is inconsistent.
    """
    if len(matrix) != len(rhs):
        raise ValueError("matrix/rhs row mismatch")
    if not matrix:
        return []
    rows = [[x % p for x in row] + [rhs[i] % p] for i, row in enumerate(matrix)]
    nvars = len(matrix[0])
    pivots: list[tuple[int, int]] = []
    r = 0
    for c in range(nvars):
        pivot = None
        for rr in range(r, len(rows)):
            if rows[rr][c] % p != 0:
                pivot = rr
                break
        if pivot is None:
            continue
        rows[r], rows[pivot] = rows[pivot], rows[r]
        inv = inv_mod(rows[r][c], p)
        rows[r] = [(v * inv) % p for v in rows[r]]
        for rr in range(len(rows)):
            if rr == r:
                continue
            factor = rows[rr][c] % p
            if factor:
                rows[rr] = [(a - factor * b) % p for a, b in zip(rows[rr], rows[r])]
        pivots.append((r, c))
        r += 1
        if r == len(rows):
            break
    for row in rows:
        if all(v % p == 0 for v in row[:nvars]) and row[nvars] % p != 0:
            raise DecodeFailure("inconsistent Berlekamp-Welch system")
    sol = [0] * nvars
    for rr, cc in pivots:
        sol[cc] = rows[rr][nvars] % p
    return sol


def rs_decode(word: list[int], modulus: int, code_dim: int) -> list[int]:
    """Decode a Reed-Solomon word using Berlekamp-Welch.

    Corrects up to floor((m-code_dim)/2) symbol errors.  Returns the recovered
    message polynomial coefficients of length code_dim.
    """
    p = modulus
    m = len(word)
    ell = code_dim
    if ell <= 0 or ell >= m:
        raise ValueError("invalid RS parameters")
    t = (m - ell) // 2
    pts = rs_points(p, m)
    if t == 0:
        # Interpolate from the first ell positions with a direct Vandermonde solve.
        matrix = [[pow(pts[i], j, p) for j in range(ell)] for i in range(ell)]
        return solve_linear_modp(matrix, [word[i] % p for i in range(ell)], p)

    # Unknowns: q_0..q_{ell+t-1}, e_0..e_{t-1}; E(x)=x^t+sum e_j x^j.
    n_q = ell + t
    n_e = t
    matrix: list[list[int]] = []
    rhs: list[int] = []
    for x, y in zip(pts, word):
        y %= p
        row = [pow(x, j, p) for j in range(n_q)]
        row += [(-y * pow(x, j, p)) % p for j in range(n_e)]
        matrix.append(row)
        rhs.append((y * pow(x, t, p)) % p)
    sol = solve_linear_modp(matrix, rhs, p)
    q_poly = sol[:n_q]
    e_poly = sol[n_q:] + [1]
    p_poly, rem = poly_divmod(q_poly, e_poly, p)
    if any(v % p for v in rem):
        raise DecodeFailure("Berlekamp-Welch quotient has nonzero remainder")
    if len(p_poly) > ell:
        raise DecodeFailure("decoded polynomial has too high degree")
    p_poly += [0] * (ell - len(p_poly))
    # Verify that the decoded codeword is sufficiently close.  This avoids
    # accepting arbitrary solutions when the error count exceeds the radius.
    codeword = rs_encode(p_poly[:ell], p, m)
    dist = sum(1 for a, b in zip(codeword, word) if (a - b) % p != 0)
    if dist > t:
        raise DecodeFailure(f"too many errors for RS radius: dist={dist}, radius={t}")
    return p_poly[:ell]


# ---------------------------------------------------------------------------
# CRT helpers


def crt_combine(residues: list[int], moduli: list[int]) -> int:
    """Combine pairwise-coprime residues into the least nonnegative residue."""
    if len(residues) != len(moduli):
        raise ValueError("residue/modulus length mismatch")
    x = 0
    M = 1
    for r, m in zip(residues, moduli):
        if math.gcd(M, m) != 1:
            raise ValueError("CRT moduli must be pairwise coprime")
        delta = ((r - x) % m) * inv_mod(M % m, m) % m
        x += M * delta
        M *= m
        x %= M
    return x


def crt_product(moduli: tuple[int, ...]) -> int:
    return reduce(mul, moduli, 1)


def c2_moduli(params: SableParams) -> tuple[int, ...]:
    mods = params.c2_moduli if params.c2_moduli else (params.q,)
    return tuple(int(m) for m in mods)


# ---------------------------------------------------------------------------
# C2 encryption / linear evaluation / decryption


def encrypt(x: int, secret_r: list[int], params: SableParams, rng: random.Random) -> C2Ciphertext:
    """Encrypt scalar x under the C2 q-ary code/LPN compactor."""
    if len(secret_r) != params.n_c:
        raise ValueError("secret length mismatch")
    channels: list[C2ChannelCiphertext] = []
    for p in c2_moduli(params):
        ell = params.c2_code_dim
        m = params.m_c
        if m >= p:
            raise ValueError(f"C2 code length {m} must be < channel modulus {p}")
        msg = [x % p] + [rng.randrange(p) for _ in range(ell - 1)]
        codeword = rs_encode(msg, p, m)
        A: list[list[int]] = []
        b: list[int] = []
        r_mod = [v % p for v in secret_r]
        for cw in codeword:
            row = [rng.randrange(p) for _ in range(params.n_c)]
            e = sample_noise(p, params.eta_c, rng)
            A.append(row)
            b.append((dot_dense(row, r_mod, p) + cw + e) % p)
        channels.append(C2ChannelCiphertext(p, A, b, ell))
    return C2Ciphertext(params.q, tuple(channels))


def decrypt(ciphertext: C2Ciphertext, secret_r: list[int]) -> int:
    """Decrypt C2 ciphertext and return the scalar payload modulo q."""
    residues: list[int] = []
    moduli: list[int] = []
    for ch in ciphertext.channels:
        if len(secret_r) != ch.n:
            raise ValueError("secret length mismatch")
        p = ch.modulus
        r_mod = [v % p for v in secret_r]
        residuals = [
            (bb - dot_dense(row, r_mod, p)) % p
            for row, bb in zip(ch.A, ch.b)
        ]
        msg = rs_decode(residuals, p, ch.code_dim)
        residues.append(msg[0] % p)
        moduli.append(p)
    if len(moduli) == 1:
        return residues[0] % ciphertext.q
    if ciphertext.q in moduli:
        return residues[moduli.index(ciphertext.q)] % ciphertext.q
    return crt_combine(residues, moduli) % ciphertext.q


def eval_lin(coeffs: SparseVector, key: list[C2Ciphertext]) -> C2Ciphertext:
    """Evaluate a sparse linear form on encrypted secret-key coordinates."""
    if len(key) != coeffs.length:
        raise ValueError("key length mismatch")
    if not key:
        raise ValueError("empty C2 key")
    first = key[0]
    acc_channels = [
        C2ChannelCiphertext.zero(ch.modulus, ch.m, ch.n, ch.code_dim)
        for ch in first.channels
    ]
    for i, coeff in coeffs.data.items():
        ct = key[i]
        if ct.moduli != first.moduli:
            raise ValueError("mixed C2 moduli in key")
        acc_channels = [a.add_scaled(b, coeff) for a, b in zip(acc_channels, ct.channels)]
    return C2Ciphertext(first.q, tuple(acc_channels))


# ---------------------------------------------------------------------------
# Estimator helpers


def binary_kl(a: float, b: float) -> float:
    if a <= 0:
        left = 0.0
    else:
        left = a * math.log(a / b)
    if a >= 1:
        right = 0.0
    else:
        right = (1 - a) * math.log((1 - a) / (1 - b))
    return left + right


def rs_failure_bound(length: int, code_dim: int, symbol_error_rate: float) -> float:
    """Chernoff/union-style upper bound for RS decoding failure.

    Failure means more than floor((m-ell)/2) symbol errors.  This is a
    correctness bound, not a security estimate.
    """
    if symbol_error_rate <= 0:
        return 0.0
    if symbol_error_rate >= 1:
        return 1.0
    radius = (length - code_dim) // 2
    threshold = (radius + 1) / length
    if symbol_error_rate >= threshold:
        return 1.0
    # Exact binomial tail for small m; KL-Chernoff for larger m.
    if length <= 256:
        tail = 0.0
        for j in range(radius + 1, length + 1):
            tail += math.comb(length, j) * (symbol_error_rate ** j) * ((1 - symbol_error_rate) ** (length - j))
        return min(1.0, tail)
    return min(1.0, math.exp(-length * binary_kl(threshold, symbol_error_rate)))


def compaction_failure_bound(params: SableParams, nonzero_terms: int) -> dict:
    """Return per-channel C2 correctness estimates for a linear form."""
    channels = []
    failures = []
    for p in c2_moduli(params):
        eta_b = qary_piling_up(p, params.eta_c, nonzero_terms)
        fail = rs_failure_bound(params.m_c, params.c2_code_dim, eta_b)
        failures.append(fail)
        channels.append({
            "modulus": p,
            "symbol_error_rate": eta_b,
            "code_length": params.m_c,
            "code_dimension": params.c2_code_dim,
            "correction_radius": (params.m_c - params.c2_code_dim) // 2,
            "failure_bound": fail,
        })
    return {
        "channels": channels,
        "union_failure_bound": min(1.0, sum(failures)),
        "crt_product": crt_product(c2_moduli(params)),
    }

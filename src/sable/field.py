"""Finite-field and q-ary noise helpers for the SABLE-HE prototype."""

from __future__ import annotations

import math
import random
from collections.abc import Sequence


def is_prime(q: int) -> bool:
    """Return True if q is a prime integer."""
    if q < 2:
        return False
    if q in (2, 3):
        return True
    if q % 2 == 0 or q % 3 == 0:
        return False
    i = 5
    while i * i <= q:
        if q % i == 0 or q % (i + 2) == 0:
            return False
        i += 6
    return True


def mod_q(x: int, q: int) -> int:
    return x % q


def sample_nonzero(q: int, rng: random.Random) -> int:
    """Sample a nonzero field element from F_q."""
    if q <= 1:
        raise ValueError("q must be at least 2")
    return rng.randrange(1, q)


def sample_field(q: int, rng: random.Random) -> int:
    return rng.randrange(q)


def sample_dense_vector(length: int, q: int, rng: random.Random) -> list[int]:
    return [rng.randrange(q) for _ in range(length)]


def sample_noise(q: int, eta: float, rng: random.Random) -> int:
    """Sample q-ary symmetric Hamming noise.

    The output is 0 with probability 1-eta and uniform nonzero otherwise.
    """
    if eta < 0 or eta > 1:
        raise ValueError("eta must be in [0, 1]")
    if rng.random() >= eta:
        return 0
    return sample_nonzero(q, rng)


def dot_dense(x: Sequence[int], y: Sequence[int], q: int) -> int:
    if len(x) != len(y):
        raise ValueError("length mismatch")
    return sum((a * b) % q for a, b in zip(x, y)) % q


def qary_piling_up(q: int, eta: float, terms: int) -> float:
    """q-ary symmetric-noise accumulation for a sum of independent terms.

    If each term is nonzero with probability eta and its nonzero value is
    uniform in F_q^*, the sum of `terms` independent errors is nonzero with
    probability

        (q-1)/q * (1 - (1 - q eta/(q-1))^terms).
    """
    if terms <= 0:
        return 0.0
    if q <= 1:
        raise ValueError("q must be at least 2")
    if eta < 0 or eta > 1:
        raise ValueError("eta must be in [0, 1]")
    base = 1.0 - (q * eta) / (q - 1)
    return ((q - 1) / q) * (1.0 - base**terms)


def qary_entropy(q: int, p: float) -> float:
    """q-ary entropy H_q(p), returned in base-q units.

    H_q(p) = p log_q(q-1) - p log_q(p) - (1-p) log_q(1-p).
    """
    if p <= 0:
        return 0.0
    if p >= 1:
        return 1.0
    return (
        p * math.log(q - 1, q)
        - p * math.log(p, q)
        - (1 - p) * math.log(1 - p, q)
    )


def repetition_failure_bound(m: int, error_rate: float) -> float:
    """Conservative failure bound for repetition/plurality decoding.

    This uses the binary-style Chernoff event that at least half of repeated
    coordinates are corrupted. For q-ary plurality this is conservative when
    nonzero errors are spread across q-1 values.
    """
    if error_rate <= 0:
        return 0.0
    if error_rate >= 0.5:
        return 1.0
    return math.exp(-2.0 * m * (0.5 - error_rate) ** 2)


def majority_failure_bound(replicas: int, per_replica_failure: float) -> float:
    """Conservative majority failure bound for independent replicas."""
    if replicas <= 1:
        return min(1.0, max(0.0, per_replica_failure))
    p = min(1.0, max(0.0, per_replica_failure))
    if p <= 0:
        return 0.0
    if p >= 0.5:
        return 1.0
    return math.exp(-2.0 * replicas * (0.5 - p) ** 2)

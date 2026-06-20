"""Small q-ary coding helpers for SABLE-HE-C2 experiments."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass


def _inv_mod(a: int, q: int) -> int:
    a %= q
    if a == 0:
        raise ZeroDivisionError("zero has no inverse")
    return pow(a, -1, q)


@dataclass(frozen=True)
class WeightedRepetitionCode:
    """One-symbol q-ary weighted repetition code.

    It encodes x as (w_1 x, ..., w_m x) with nonzero public weights.  Decoding
    divides by the weights and performs deterministic plurality.  For scalar
    messages this is equivalent to generalized repetition, but it is useful as
    a clean C2 test abstraction and avoids all-zero structural rows.
    """

    weights: tuple[int, ...]
    q: int

    def __post_init__(self) -> None:
        if not self.weights:
            raise ValueError("weights cannot be empty")
        if self.q < 2:
            raise ValueError("q must be at least 2")
        if any((w % self.q) == 0 for w in self.weights):
            raise ValueError("weights must be nonzero modulo q")

    @classmethod
    def deterministic(cls, m: int, q: int) -> "WeightedRepetitionCode":
        if m <= 0:
            raise ValueError("m must be positive")
        return cls(tuple((i % (q - 1)) + 1 for i in range(m)), q)

    def encode(self, x: int) -> list[int]:
        return [(w * x) % self.q for w in self.weights]

    def decode(self, residuals: list[int]) -> int:
        if len(residuals) != len(self.weights):
            raise ValueError("residual length mismatch")
        votes = [((y % self.q) * _inv_mod(w, self.q)) % self.q for y, w in zip(residuals, self.weights)]
        counts = Counter(votes)
        return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def _chernoff_lower_half(mu: float) -> float:
    if mu <= 0:
        return 1.0
    # Pr[X <= mu/2] <= exp(-mu/8)
    return math.exp(-mu / 8.0)


def _chernoff_upper_ge(mu: float, threshold: float) -> float:
    if threshold <= mu:
        return 1.0
    if mu <= 0:
        return 0.0
    delta = threshold / mu - 1.0
    # Pr[X >= (1+delta)mu] <= (e^delta/(1+delta)^(1+delta))^mu
    log_bound = mu * (delta - (1.0 + delta) * math.log1p(delta))
    return math.exp(min(0.0, log_bound))


def qary_plurality_failure_bound(m: int, q: int, error_rate: float) -> float:
    """Conservative bound for q-ary plurality decoding.

    A binary repetition bound treats every corrupted coordinate as voting for a
    single adversarial wrong value.  q-ary symmetric noise spreads corrupted
    votes among q-1 wrong symbols.  This function upper-bounds the event that
    the correct symbol receives unusually few votes or some wrong symbol catches
    up.  It is a screening bound, not a tight coding theorem.
    """
    if m <= 0:
        raise ValueError("m must be positive")
    if q < 2:
        raise ValueError("q must be at least 2")
    p = min(1.0, max(0.0, error_rate))
    if p <= 0:
        return 0.0
    if p >= 1.0:
        return 1.0
    mu_good = m * (1.0 - p)
    threshold = max(1.0, mu_good / 2.0)
    low_good = _chernoff_lower_half(mu_good)
    mu_bad = m * p / max(1, q - 1)
    high_bad = min(1.0, (q - 1) * _chernoff_upper_ge(mu_bad, threshold))
    return min(1.0, low_good + high_bad)

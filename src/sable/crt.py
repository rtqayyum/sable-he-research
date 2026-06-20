"""Chinese Remainder Theorem helpers for small experimental lanes."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class CRTModuli:
    moduli: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.moduli:
            raise ValueError("at least one modulus is required")
        if any(m <= 1 for m in self.moduli):
            raise ValueError("moduli must be greater than 1")
        for i, a in enumerate(self.moduli):
            for b in self.moduli[i + 1 :]:
                if math.gcd(a, b) != 1:
                    raise ValueError("moduli must be pairwise coprime")

    @property
    def modulus(self) -> int:
        out = 1
        for m in self.moduli:
            out *= m
        return out

    def residues(self, x: int) -> tuple[int, ...]:
        return tuple(x % m for m in self.moduli)

    def reconstruct(self, residues: tuple[int, ...] | list[int]) -> int:
        if len(residues) != len(self.moduli):
            raise ValueError("residue count mismatch")
        M = self.modulus
        total = 0
        for r, m in zip(residues, self.moduli):
            Mi = M // m
            total += (r % m) * Mi * pow(Mi, -1, m)
        return total % M

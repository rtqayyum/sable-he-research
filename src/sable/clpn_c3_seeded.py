"""Seeded C3 block-dictionary compaction for SABLE-HE.

C3 keeps the C2 block-dictionary semantics but replaces each dense CLPN matrix
A with a public seed.  The public key still stores one b-vector per dictionary
entry, so the public LPN sample count is unchanged.  The gain is materialized
storage and memory traffic, not a stronger security claim.
"""

from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass

from . import clpn_seeded
from .field import dot_dense
from .params import SableParams
from .sparse import SparseVector


@dataclass(frozen=True)
class SeededC2BlockDictionaryKey:
    q: int
    N: int
    block_size: int
    n_c: int
    m_c: int
    blocks: list[dict[tuple[int, ...], clpn_seeded.SeededCLPNCiphertext]]

    def __post_init__(self) -> None:
        if self.N <= 0:
            raise ValueError("N must be positive")
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")
        expected_blocks = math.ceil(self.N / self.block_size)
        if len(self.blocks) != expected_blocks:
            raise ValueError("incorrect number of C3 blocks")
        for block_index, table in enumerate(self.blocks):
            width = self.block_width(block_index)
            for coeffs, ct in table.items():
                if len(coeffs) != width:
                    raise ValueError("coefficient tuple has wrong block width")
                if all((c % self.q) == 0 for c in coeffs):
                    raise ValueError("zero tuple should not be stored")
                if ct.q != self.q or ct.n != self.n_c or ct.m != self.m_c:
                    raise ValueError("seeded CLPN ciphertext incompatible with C3 key")

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    @property
    def public_entries(self) -> int:
        return sum(len(block) for block in self.blocks)

    def block_width(self, block_index: int) -> int:
        start = block_index * self.block_size
        return max(0, min(self.block_size, self.N - start))


def _all_nonzero_tuples(q: int, width: int):
    for coeffs in itertools.product(range(q), repeat=width):
        if any(coeffs):
            yield coeffs


def coeff_blocks(coeffs: SparseVector, block_size: int) -> list[tuple[int, ...]]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    q = coeffs.q
    out: list[tuple[int, ...]] = []
    for start in range(0, coeffs.length, block_size):
        width = min(block_size, coeffs.length - start)
        out.append(tuple(coeffs.data.get(start + j, 0) % q for j in range(width)))
    return out


def nonzero_block_count(coeffs: SparseVector, block_size: int) -> int:
    return sum(1 for block in coeff_blocks(coeffs, block_size) if any(block))


def build_seeded_dictionary(
    tilde_s: list[int],
    secret_r: list[int],
    params: SableParams,
    rng: random.Random,
    *,
    block_size: int | None = None,
) -> SeededC2BlockDictionaryKey:
    q = params.q
    N = len(tilde_s)
    ell = params.c2_block_size if block_size is None else block_size
    if ell <= 0:
        raise ValueError("block_size must be positive")
    if N != params.N:
        raise ValueError("tilde_s length must equal params.N")
    if len(secret_r) != params.n_c:
        raise ValueError("compaction secret length mismatch")
    blocks: list[dict[tuple[int, ...], clpn_seeded.SeededCLPNCiphertext]] = []
    for start in range(0, N, ell):
        s_block = tilde_s[start : min(start + ell, N)]
        table: dict[tuple[int, ...], clpn_seeded.SeededCLPNCiphertext] = {}
        for coeffs in _all_nonzero_tuples(q, len(s_block)):
            msg = dot_dense(coeffs, s_block, q)
            table[tuple(c % q for c in coeffs)] = clpn_seeded.encrypt(msg, secret_r, params, rng)
        blocks.append(table)
    return SeededC2BlockDictionaryKey(q=q, N=N, block_size=ell, n_c=params.n_c, m_c=params.m_c, blocks=blocks)


def eval_lin_seeded(coeffs: SparseVector, key: SeededC2BlockDictionaryKey) -> clpn_seeded.SeededCLPNCiphertext:
    if coeffs.length != key.N or coeffs.q != key.q:
        raise ValueError("coefficient vector incompatible with C3 key")
    acc = clpn_seeded.SeededCLPNCiphertext.zero(key.m_c, key.n_c, key.q)
    for block_index, block in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block):
            continue
        acc = acc.add(key.blocks[block_index][block])
    return acc

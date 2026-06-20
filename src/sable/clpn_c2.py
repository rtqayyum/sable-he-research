"""C2 block-dictionary q-ary LPN compaction layer.

The legacy compactor publishes one CLPN encryption of each extended-secret
coordinate.  A final row with B nonzero coordinates then accumulates B CLPN
noise vectors.  C2 partitions the extended secret into small blocks of length
ell and publishes CLPN encryptions of every nonzero block inner product
<u, s_block>.  Compaction uses at most one ciphertext per nonzero block.

This reduces compaction noise from roughly B terms to at most ceil(N/ell)
terms, at the cost of a larger public key of size sum_j (q^{ell_j}-1) CLPN
ciphertexts.  This is only viable for small q and small ell, and is provided as
a research-validation prototype rather than production cryptography.
"""

from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass

from . import clpn
from .field import dot_dense
from .params import SableParams
from .sparse import SparseVector


@dataclass(frozen=True)
class C2BlockDictionaryKey:
    q: int
    N: int
    block_size: int
    n_c: int
    m_c: int
    blocks: list[dict[tuple[int, ...], clpn.CLPNCiphertext]]

    def __post_init__(self) -> None:
        if self.N <= 0:
            raise ValueError("N must be positive")
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")
        expected_blocks = math.ceil(self.N / self.block_size)
        if len(self.blocks) != expected_blocks:
            raise ValueError("incorrect number of C2 blocks")
        for block_index, table in enumerate(self.blocks):
            width = self.block_width(block_index)
            for coeffs, ct in table.items():
                if len(coeffs) != width:
                    raise ValueError("coefficient tuple has wrong block width")
                if all((c % self.q) == 0 for c in coeffs):
                    raise ValueError("zero tuple should not be stored")
                if ct.q != self.q or ct.n != self.n_c or ct.m != self.m_c:
                    raise ValueError("CLPN ciphertext incompatible with C2 key")

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


def build_dictionary(
    tilde_s: list[int],
    secret_r: list[int],
    params: SableParams,
    rng: random.Random,
    *,
    block_size: int | None = None,
) -> C2BlockDictionaryKey:
    q = params.q
    N = len(tilde_s)
    ell = params.c2_block_size if block_size is None else block_size
    if ell <= 0:
        raise ValueError("block_size must be positive")
    if N != params.N:
        raise ValueError("tilde_s length must equal params.N")
    if len(secret_r) != params.n_c:
        raise ValueError("compaction secret length mismatch")
    blocks: list[dict[tuple[int, ...], clpn.CLPNCiphertext]] = []
    for start in range(0, N, ell):
        s_block = tilde_s[start : min(start + ell, N)]
        table: dict[tuple[int, ...], clpn.CLPNCiphertext] = {}
        for coeffs in _all_nonzero_tuples(q, len(s_block)):
            msg = dot_dense(coeffs, s_block, q)
            table[tuple(c % q for c in coeffs)] = clpn.encrypt(msg, secret_r, params, rng)
        blocks.append(table)
    return C2BlockDictionaryKey(q=q, N=N, block_size=ell, n_c=params.n_c, m_c=params.m_c, blocks=blocks)


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


def eval_lin(coeffs: SparseVector, key) -> clpn.CLPNCiphertext:
    """Evaluate a linear form with either block-dictionary or legacy C2 key."""
    if isinstance(key, C2BlockDictionaryKey):
        if coeffs.length != key.N or coeffs.q != key.q:
            raise ValueError("coefficient vector incompatible with C2 key")
        acc = clpn.CLPNCiphertext.zero(key.m_c, key.n_c, key.q)
        for block_index, block in enumerate(coeff_blocks(coeffs, key.block_size)):
            if not any(block):
                continue
            acc = acc.add(key.blocks[block_index][block])
        return acc
    # Compatibility path: list of scalar CLPN ciphertexts.
    return clpn.eval_lin(coeffs, key)

# Compatibility layer for the earlier C2 validation API.  The earlier design
# described "packed" and "chunked" compaction.  For compatibility, these names
# wrap the legacy CLPN ciphertext.  The block-dictionary C2 API above remains
# available through build_dictionary/eval_lin.
C2Ciphertext = clpn.CLPNCiphertext
PackedCLPNCiphertext = C2Ciphertext
ChunkedPackedCLPNCiphertext = C2Ciphertext


def make_code(params: SableParams, rng: random.Random | None = None, deterministic: bool = False):
    """Compatibility hook for older code-based C2 experiments."""
    del rng, deterministic
    from .codes import WeightedRepetitionCode

    return WeightedRepetitionCode.deterministic(params.m_c, params.q)


def encrypt(x: int, secret_r: list[int], params: SableParams, rng: random.Random, code=None) -> C2Ciphertext:
    """Compatibility encryption routine.

    The code argument is accepted for old callers.  The current executable
    prototype delegates to the CLPN scalar encryption layer.
    """
    del code
    return clpn.encrypt(x, secret_r, params, rng)


def decrypt(ciphertext: C2Ciphertext, secret_r: list[int]) -> int:
    return clpn.decrypt(ciphertext, secret_r)


def make_compaction_key(
    tilde_s: list[int],
    secret_r: list[int],
    params: SableParams,
    rng: random.Random,
) -> list[C2Ciphertext]:
    """Build a compatibility C2 compaction key encrypting coordinates."""
    return [encrypt(coord, secret_r, params, rng) for coord in tilde_s]


def compact_row_c2(row: SparseVector, key: list[C2Ciphertext], params: SableParams) -> C2Ciphertext:
    """Compact a final GSW row using the compatibility C2 compaction key."""
    del params
    return clpn.eval_lin(row, key)


def decrypt_chunked(ciphertext: C2Ciphertext, secret_r: list[int]) -> int:
    """Decrypt a C2 compact ciphertext; compatibility name."""
    return decrypt(ciphertext, secret_r)

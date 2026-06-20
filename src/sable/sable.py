"""End-to-end SABLE-HE research prototype API.

The module exposes the legacy coordinate compactor, C2 block dictionary, C3
seeded dictionary, C4 projective/sparse additive-basis compaction, and the C7
relation-resistant compactor.  C7 coordinate mode is the conservative research
default after the C6 projective-relation screen.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass
from typing import Any

from . import clpn, gsw, regev
from .c7_relation_resistant import C7BasisKey, build_basis_key as build_c7_basis_key, decrypt_c7 as c7_decrypt_one, eval_lin as eval_lin_c7
from .clpn_c2 import C2BlockDictionaryKey, C2Ciphertext, build_dictionary, compact_row_c2, decrypt_chunked, eval_lin as eval_lin_c2, make_compaction_key
from .clpn_c3_seeded import SeededC2BlockDictionaryKey, build_seeded_dictionary, eval_lin_seeded
from .clpn_c4_basis import C4BasisKey, build_basis_key as build_c4_basis_key, decrypt_c4, eval_lin as eval_lin_c4
from .clpn_seeded import SeededCLPNCiphertext, decrypt as decrypt_seeded_one
from .field import sample_dense_vector
from .params import SableParams
from .sparse import SparseMatrix, SparseVector


@dataclass(frozen=True)
class KeyPair:
    params: SableParams
    t: list[int]
    s: list[int]
    r: list[int]
    expansion_key: list[SparseMatrix]
    compaction_key: list[clpn.CLPNCiphertext]
    compaction_key_c2: list[C2Ciphertext] | None = None
    compaction_dictionary_c2: C2BlockDictionaryKey | None = None
    compaction_seeded_dictionary_c2: SeededC2BlockDictionaryKey | None = None
    compaction_basis_c4: C4BasisKey | None = None
    compaction_basis_c7: C7BasisKey | None = None


def _rng(seed: int | None) -> random.Random:
    return random.Random(seed)


def _base_key_material(params: SableParams, rng: random.Random):
    q = params.q
    t = sample_dense_vector(params.n, q, rng)
    s = sample_dense_vector(params.n, q, rng)
    r = sample_dense_vector(params.n_c, q, rng)
    tilde_t = regev.extended_secret(t, q)
    tilde_s = regev.extended_secret(s, q)
    expansion_key = [gsw.encrypt(coord, s, params, rng) for coord in tilde_t]
    return t, s, r, tilde_s, expansion_key


def keygen(params: SableParams, seed: int | None = None) -> KeyPair:
    rng = _rng(seed)
    t, s, r, tilde_s, expansion_key = _base_key_material(params, rng)
    compaction_key = [clpn.encrypt(coord, r, params, rng) for coord in tilde_s]
    return KeyPair(params, t, s, r, expansion_key, compaction_key)


def keygen_c2(params: SableParams, seed: int | None = None, *, include_legacy: bool = False) -> KeyPair:
    rng = _rng(seed)
    t, s, r, tilde_s, expansion_key = _base_key_material(params, rng)
    compaction_key = [clpn.encrypt(coord, r, params, rng) for coord in tilde_s] if include_legacy else []
    compaction_key_c2 = make_compaction_key(tilde_s, r, params, rng)
    return KeyPair(params, t, s, r, expansion_key, compaction_key, compaction_key_c2)


def keygen_block_c2(params: SableParams, seed: int | None = None, *, block_size: int | None = None, include_legacy: bool = False) -> KeyPair:
    rng = _rng(seed)
    t, s, r, tilde_s, expansion_key = _base_key_material(params, rng)
    compaction_key = [clpn.encrypt(coord, r, params, rng) for coord in tilde_s] if include_legacy else []
    dictionary = build_dictionary(tilde_s, r, params, rng, block_size=block_size)
    return KeyPair(params, t, s, r, expansion_key, compaction_key, None, dictionary)


def keygen_seeded_block_c2(params: SableParams, seed: int | None = None, *, block_size: int | None = None, include_legacy: bool = False) -> KeyPair:
    rng = _rng(seed)
    t, s, r, tilde_s, expansion_key = _base_key_material(params, rng)
    compaction_key = [clpn.encrypt(coord, r, params, rng) for coord in tilde_s] if include_legacy else []
    dictionary = build_seeded_dictionary(tilde_s, r, params, rng, block_size=block_size)
    return KeyPair(params, t, s, r, expansion_key, compaction_key, None, None, dictionary)


def keygen_basis_c4(
    params: SableParams,
    seed: int | None = None,
    *,
    block_size: int | None = None,
    basis_size: int | None = None,
    entries_per_full_block: int | None = None,
    max_terms_per_block: int = 1,
    mode: str = "projective",
    include_legacy: bool = False,
    **kwargs: object,
) -> KeyPair:
    rng = _rng(seed)
    t, s, r, tilde_s, expansion_key = _base_key_material(params, rng)
    compaction_key = [clpn.encrypt(coord, r, params, rng) for coord in tilde_s] if include_legacy else []
    basis_key = build_c4_basis_key(
        tilde_s,
        r,
        params,
        rng,
        block_size=block_size,
        basis_size=basis_size,
        entries_per_full_block=entries_per_full_block,
        max_terms_per_block=max_terms_per_block,
        mode=mode,  # type: ignore[arg-type]
        **kwargs,
    )
    return KeyPair(params, t, s, r, expansion_key, compaction_key, None, None, None, basis_key)


def keygen_c4_basis(*args: Any, **kwargs: Any) -> KeyPair:
    return keygen_basis_c4(*args, **kwargs)


def keygen_c4_sparse_basis(*args: Any, **kwargs: Any) -> KeyPair:
    return keygen_basis_c4(*args, **kwargs)


def keygen_relation_resistant_c7(
    params: SableParams,
    seed: int | None = None,
    *,
    block_size: int | None = None,
    mode: str = "coordinate",
    entries_per_block: int | None = None,
    preferred_terms_per_block: int | None = None,
    relation_screen_weight: int = 4,
    include_legacy: bool = False,
) -> KeyPair:
    rng = _rng(seed)
    t, s, r, tilde_s, expansion_key = _base_key_material(params, rng)
    compaction_key = [clpn.encrypt(coord, r, params, rng) for coord in tilde_s] if include_legacy else []
    basis_key = build_c7_basis_key(
        tilde_s,
        r,
        params,
        rng,
        block_size=block_size,
        mode=mode,  # type: ignore[arg-type]
        entries_per_block=entries_per_block,
        preferred_terms_per_block=preferred_terms_per_block,
        relation_screen_weight=relation_screen_weight,
    )
    return KeyPair(params, t, s, r, expansion_key, compaction_key, None, None, None, None, basis_key)


def keygen_c7(*args: Any, **kwargs: Any) -> KeyPair:
    return keygen_relation_resistant_c7(*args, **kwargs)


def keygen_c7_relation_resistant(*args: Any, **kwargs: Any) -> KeyPair:
    return keygen_relation_resistant_c7(*args, **kwargs)


def keygen_screened_c7(
    params: SableParams,
    seed: int | None = None,
    *,
    block_size: int | None = None,
    extra_masks_per_block: int = 0,
    min_mask_support: int = 3,
    forbid_weight3: bool = True,
    max_terms_per_block: int | None = None,
    max_attempts_per_block: int = 10000,
    include_legacy: bool = False,
) -> KeyPair:
    # Backward-compatible C7 screened API.  The relation-resistant module uses
    # a standard coordinate fallback and optional screened-random masks.
    del min_mask_support, forbid_weight3, max_attempts_per_block
    entries = None
    mode = "coordinate"
    if extra_masks_per_block > 0:
        ell = params.c2_block_size if block_size is None else block_size
        entries = ell + extra_masks_per_block
        mode = "screened-random"
    return keygen_relation_resistant_c7(
        params,
        seed=seed,
        block_size=block_size,
        mode=mode,
        entries_per_block=entries,
        preferred_terms_per_block=max_terms_per_block,
        include_legacy=include_legacy,
    )


def keygen_c7_screened(*args: Any, **kwargs: Any) -> KeyPair:
    return keygen_screened_c7(*args, **kwargs)


def keygen_basis_c7(*args: Any, **kwargs: Any) -> KeyPair:
    return keygen_relation_resistant_c7(*args, **kwargs)


def encrypt(kp: KeyPair, mu: int, seed: int | None = None) -> list[SparseVector]:
    rng = _rng(seed)
    return [regev.encrypt(mu % kp.params.q, kp.t, kp.params, rng) for _ in range(kp.params.replicas)]


def expand(kp: KeyPair, ciphertext: list[SparseVector]) -> list[SparseMatrix]:
    return [gsw.expand_vector(c, kp.expansion_key) for c in ciphertext]


def eval_add(left: list[SparseMatrix], right: list[SparseMatrix]) -> list[SparseMatrix]:
    if len(left) != len(right):
        raise ValueError("replica mismatch")
    return [gsw.eval_add(a, b) for a, b in zip(left, right)]


def eval_mul(left: list[SparseMatrix], right: list[SparseMatrix], *, oriented: bool = False) -> list[SparseMatrix]:
    if len(left) != len(right):
        raise ValueError("replica mismatch")
    if oriented:
        return [gsw.eval_mul_oriented(a, b) for a, b in zip(left, right)]
    return [gsw.eval_mul(a, b) for a, b in zip(left, right)]


def compact(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    if not kp.compaction_key:
        raise ValueError("legacy compaction key is not present")
    return [clpn.eval_lin(C.last_row(), kp.compaction_key) for C in expanded_ciphertext]


def compact_c2(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[C2Ciphertext]:
    if kp.compaction_key_c2 is None:
        raise ValueError("C2 compaction key is not present")
    return [compact_row_c2(C.last_row(), kp.compaction_key_c2, kp.params) for C in expanded_ciphertext]


def compact_block_c2(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    if kp.compaction_dictionary_c2 is None:
        raise ValueError("block-dictionary C2 key is not present")
    return [eval_lin_c2(C.last_row(), kp.compaction_dictionary_c2) for C in expanded_ciphertext]


def compact_seeded_block_c2(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[SeededCLPNCiphertext]:
    if kp.compaction_seeded_dictionary_c2 is None:
        raise ValueError("seeded block-dictionary key is not present")
    return [eval_lin_seeded(C.last_row(), kp.compaction_seeded_dictionary_c2) for C in expanded_ciphertext]


def compact_basis_c4(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    if kp.compaction_basis_c4 is None:
        raise ValueError("C4 basis key is not present")
    return [eval_lin_c4(C.last_row(), kp.compaction_basis_c4) for C in expanded_ciphertext]


def compact_c4_basis(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    return compact_basis_c4(kp, expanded_ciphertext)


def compact_c4_sparse_basis(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    return compact_basis_c4(kp, expanded_ciphertext)


def compact_relation_resistant_c7(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    if kp.compaction_basis_c7 is None:
        raise ValueError("C7 relation-resistant key is not present")
    return [eval_lin_c7(C.last_row(), kp.compaction_basis_c7) for C in expanded_ciphertext]


def compact_c7(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    return compact_relation_resistant_c7(kp, expanded_ciphertext)


def compact_screened_c7(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    return compact_relation_resistant_c7(kp, expanded_ciphertext)


def compact_c7_screened(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    return compact_relation_resistant_c7(kp, expanded_ciphertext)


def compact_basis_c7(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> list[clpn.CLPNCiphertext]:
    return compact_relation_resistant_c7(kp, expanded_ciphertext)


def decrypt(kp: KeyPair, compact_ciphertext: list[Any]) -> int:
    if compact_ciphertext and isinstance(compact_ciphertext[0], SeededCLPNCiphertext):
        return decrypt_seeded_block_c2(kp, compact_ciphertext)  # type: ignore[arg-type]
    if compact_ciphertext and isinstance(compact_ciphertext[0], C2Ciphertext):
        return decrypt_c2(kp, compact_ciphertext)  # type: ignore[arg-type]
    values = [clpn.decrypt(c, kp.r) for c in compact_ciphertext]
    counts = Counter(values)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def decrypt_c2(kp: KeyPair, compact_ciphertext: list[C2Ciphertext]) -> int:
    values = [decrypt_chunked(c, kp.r) for c in compact_ciphertext]
    counts = Counter(values)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def decrypt_block_c2(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt(kp, compact_ciphertext)


def decrypt_seeded_block_c2(kp: KeyPair, compact_ciphertext: list[SeededCLPNCiphertext]) -> int:
    values = [decrypt_seeded_one(c, kp.r) for c in compact_ciphertext]
    counts = Counter(values)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def decrypt_basis_c4(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    values = [decrypt_c4(c, kp.r) for c in compact_ciphertext]
    counts = Counter(values)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def decrypt_c4_basis(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_basis_c4(kp, compact_ciphertext)


def decrypt_c4_sparse_basis(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_basis_c4(kp, compact_ciphertext)


def decrypt_relation_resistant_c7(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    values = [c7_decrypt_one(c, kp.r) for c in compact_ciphertext]
    counts = Counter(values)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]


def decrypt_c7_ciphertext(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_relation_resistant_c7(kp, compact_ciphertext)


def decrypt_basis_c7(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_relation_resistant_c7(kp, compact_ciphertext)


def decrypt_screened_c7(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_relation_resistant_c7(kp, compact_ciphertext)


def decrypt_c7_screened(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_relation_resistant_c7(kp, compact_ciphertext)


def decrypt_c7(kp: KeyPair, compact_ciphertext: list[clpn.CLPNCiphertext]) -> int:
    return decrypt_relation_resistant_c7(kp, compact_ciphertext)


def direct_decrypt_gsw(kp: KeyPair, expanded_ciphertext: list[SparseMatrix]) -> int:
    values = [gsw.direct_decrypt_lastrow(C, kp.s) for C in expanded_ciphertext]
    counts = Counter(values)
    return max(counts.items(), key=lambda item: (item[1], -item[0]))[0]

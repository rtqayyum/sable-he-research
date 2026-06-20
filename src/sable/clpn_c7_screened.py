"""Compatibility wrapper for the C7 relation-resistant compactor.

The maintained C7 implementation lives in :mod:`sable.c7_relation_resistant`.
This wrapper preserves earlier C7-screened experiment names and accepts the
older argument names (``target_size`` and ``min_relation_weight``).
"""

from __future__ import annotations

import random
from typing import Any

from . import c7_relation_resistant as _rr

C7ScreenedBasisKey = _rr.C7BasisKey
C7RelationResistantKey = _rr.C7BasisKey

standard_basis = _rr.standard_basis
low_weight_relation_exists = _rr.low_weight_relation_exists
first_relation_weight = _rr.first_relation_weight
block_relation_profile = _rr.block_relation_profile
coordinate_combination = _rr.coordinate_combination
decompose_c7 = _rr.decompose_c7
coeff_blocks = _rr.coeff_blocks
eval_lin = _rr.eval_lin
eval_lin_c7 = _rr.eval_lin
compaction_term_count = _rr.compaction_term_count
terms_used = _rr.compaction_term_count
term_count = _rr.compaction_term_count
decrypt_c7 = _rr.decrypt_c7
readiness_summary = _rr.readiness_summary


def build_screened_basis(q: int, width: int, rng: random.Random, *, target_size: int | None = None, min_relation_weight: int = 4, max_attempts: int = 20000, **_: Any):
    entries = target_size if target_size is not None else width + 2
    return _rr.build_screened_basis(q, width, entries, rng, min_relation_weight=min_relation_weight, max_attempts=max_attempts)


def build_screened_basis_key(*args: Any, target_size: int | None = None, min_relation_weight: int | None = None, **kwargs: Any):
    if target_size is None and "basis_size" in kwargs:
        target_size = kwargs.pop("basis_size")
    else:
        kwargs.pop("basis_size", None)
    if target_size is not None and "entries_per_block" not in kwargs:
        kwargs["entries_per_block"] = target_size
    if "max_terms_per_block" in kwargs and "preferred_terms_per_block" not in kwargs:
        kwargs["preferred_terms_per_block"] = kwargs.pop("max_terms_per_block")
    if min_relation_weight is not None and "relation_screen_weight" not in kwargs:
        kwargs["relation_screen_weight"] = min_relation_weight
    if "mode" not in kwargs:
        kwargs["mode"] = "screened-random"
    kwargs["mode"] = "screened-random" if kwargs.get("mode") in {"screened_random", "screened-random", "random"} else ("coordinate" if kwargs.get("mode") in {"standard", "coordinate"} else kwargs.get("mode"))
    return _rr.build_basis_key(*args, **kwargs)


def build_basis_key(*args: Any, **kwargs: Any):
    return build_screened_basis_key(*args, **kwargs)


def build_c7_basis_key(*args: Any, **kwargs: Any):
    return build_screened_basis_key(*args, **kwargs)


def build_c7_screened_key(*args: Any, **kwargs: Any):
    return build_screened_basis_key(*args, **kwargs)


def estimate_c7_key(params, *, block_size=None, target_size=None, min_relation_weight=None, mode="screened-random", **kwargs: Any):
    if target_size is None:
        target_size = kwargs.pop("basis_size", None)
    else:
        kwargs.pop("basis_size", None)
    if "max_terms_per_block" in kwargs and "preferred_terms_per_block" not in kwargs:
        kwargs["preferred_terms_per_block"] = kwargs.pop("max_terms_per_block")
    basis_size = kwargs.pop("basis_size", None)
    entries_per_block = kwargs.pop("entries_per_block", target_size if target_size is not None else basis_size)
    max_terms = kwargs.pop("max_terms_per_block", None)
    if max_terms is not None and "preferred_terms_per_block" not in kwargs:
        kwargs["preferred_terms_per_block"] = max_terms
    relation_screen_weight = kwargs.pop("relation_screen_weight", min_relation_weight if min_relation_weight is not None else 4)
    return _rr.estimate_c7_key(
        params,
        block_size=block_size,
        mode=("screened-random" if mode in {"screened_random", "screened-random", "random"} else ("coordinate" if mode in {"standard", "coordinate"} else mode)),
        entries_per_block=entries_per_block,
        relation_screen_weight=relation_screen_weight,
        **kwargs,
    )


def relation_free_up_to(q: int, basis, max_relation_weight: int) -> bool:
    return _rr.first_relation_weight(q, basis, max_relation_weight) is None

"""Compatibility wrapper for the q-ary plurality C2 compactor experiments.

The block-dictionary C2 API lives in :mod:`sable.sable` as keygen_c2 and
compact_c2.  This module preserves the earlier v3 API used by tests and docs.
For clean toy tests it delegates to the legacy coordinate compactor while the
new block-dictionary implementation is exercised separately through
``sable.sable.keygen_c2``.
"""

from __future__ import annotations

from .sable import compact, decrypt, direct_decrypt_gsw, encrypt, eval_add, eval_mul, expand, keygen as _keygen
from .params import SableParams


def keygen(params: SableParams, seed: int | None = None, *, deterministic_code: bool = False):
    # deterministic_code is accepted for API compatibility.
    return _keygen(params, seed=seed)

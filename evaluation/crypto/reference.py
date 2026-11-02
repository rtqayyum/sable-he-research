"""Attack the reference implementation's own presets with the known-plaintext attack."""

from __future__ import annotations

import random
import time
import warnings
from typing import Any

import numpy as np


def crosscheck(cfg: dict[str, Any]) -> dict[str, Any]:
    from sable import PRESETS
    from sable.gsw import direct_decrypt_lastrow
    from sable.params import InsecureParametersWarning
    from sable.sable import KeyPair, _base_key_material, encrypt, expand
    from sable.sparse_attacks import recover_s_known_plaintext

    p = PRESETS[cfg["preset"]]
    seed = int(cfg["seed"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureParametersWarning)
        t, s, r, _, xkey = _base_key_material(p, random.Random(seed))
    rows = [row.data for row in xkey[p.n].rows]
    t0 = time.perf_counter()
    s_hat = recover_s_known_plaintext(rows, p.n, p.q)
    secs = time.perf_counter() - t0
    ok = s_hat is not None and [int(x) for x in s_hat] == list(s)
    decrypted = None
    if ok:
        kp = KeyPair(p, t, s, r, xkey, [])
        mu = random.Random(seed + 1).randrange(p.q)
        ct = expand(kp, encrypt(kp, mu, seed=seed + 2))
        vals = [direct_decrypt_lastrow(C, [int(x) for x in s_hat]) for C in ct]
        decrypted = max(set(vals), key=vals.count) == mu
    return {"preset": p.name, "n": p.n, "k": p.k, "eta": p.eta, "q": p.q, "success": ok, "decrypted_client_value": decrypted,
            "predicted_success": (1 - p.eta) ** (p.n + 1), "seconds": secs}


def feasible_presets(max_n: int = 600) -> list[str]:
    from sable import PRESETS

    return sorted(name for name, p in PRESETS.items() if p.n <= max_n)

#!/usr/bin/env python3
"""Run C4 coverage and relation screens."""

from __future__ import annotations

import json
import random
from sable.additive_basis import projective_representatives, random_basis
from sable.clpn_c4_basis import screen_basis
from sable.params import PRESETS


def main() -> None:
    params = PRESETS["c2_toy_clean"]
    q = params.q
    width = params.c2_block_size
    rng = random.Random(2026)
    projective = projective_representatives(q, width)
    random_codebook = random_basis(q, width, 12, rng, include_standard=True)
    out = {
        "preset": params.name,
        "projective_T1": screen_basis(q, width, projective, 1, rng, samples=100, relation_weight=3),
        "random_M12_T2": screen_basis(q, width, random_codebook, 2, rng, samples=100, relation_weight=3),
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare legacy, C2/C3 full dictionary, and C4 projective public surfaces."""

from __future__ import annotations

import json
from dataclasses import asdict
from sable.c4_estimator import compare
from sable.params import PRESETS


def main() -> None:
    rows = []
    for name in ["c2_toy_clean", "c2_design_smallq"]:
        params = PRESETS[name]
        rows.append(asdict(compare(params, block_size=params.c2_block_size, max_terms_per_block=1)))
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

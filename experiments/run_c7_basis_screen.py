#!/usr/bin/env python3
"""Screen C7 coordinate and experimental screened-random bases."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.c7_relation_resistant import (
    block_relation_profile,
    build_screened_basis,
    estimate_c7_key,
    standard_basis,
)
from sable.params import PRESETS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c4_projective_toy_clean', choices=sorted(PRESETS))
    parser.add_argument('--q', type=int, default=None)
    parser.add_argument('--width', type=int, default=4)
    parser.add_argument('--entries', type=int, default=6)
    parser.add_argument('--seed', type=int, default=77)
    parser.add_argument('--json-output', type=Path, default=None)
    args = parser.parse_args()
    params = PRESETS[args.preset]
    q = args.q or params.q
    rng = random.Random(args.seed)
    coord = standard_basis(args.width)
    screened = build_screened_basis(q, args.width, args.entries, rng, min_relation_weight=4)
    report = {
        'coordinate_profile': block_relation_profile(q, coord, screen_weight=4),
        'screened_random_profile': block_relation_profile(q, screened, screen_weight=4),
        'screened_random_basis': [list(v) for v in screened],
        'estimator_coordinate_block1': estimate_c7_key(params, block_size=1, mode='coordinate'),
        'estimator_screened_random': estimate_c7_key(params, block_size=args.width, mode='screened-random', entries_per_block=args.entries),
        'note': 'Screened-random is experimental. Coordinate C7 remains the main relation-resistant profile.',
    }
    if args.json_output:
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    print(json.dumps(report, indent=2, sort_keys=True, default=str))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.c5_surface import estimate_c5_surface
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c4_projective_toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--block-size', type=int, default=None)
    parser.add_argument('--relation-trials', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=123)
    parser.add_argument('--json-output', type=Path, default=None)
    args = parser.parse_args()
    report = estimate_c5_surface(PRESETS[args.preset], block_size=args.block_size, relation_trials=args.relation_trials, seed=args.seed)
    data = asdict(report)
    if args.json_output:
        args.json_output.write_text(json.dumps(data, indent=2, sort_keys=True))
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

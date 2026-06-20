#!/usr/bin/env python3
"""Generate the C7 final readiness report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.c4_estimator import estimate_c4_key
from sable.c6_relation_estimator import surface_counts
from sable.c7_relation_resistant import estimate_c7_key, readiness_summary
from sable.params import PRESETS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preset', default='c4_projective_toy_clean', choices=sorted(PRESETS))
    parser.add_argument('--json-output', type=Path, default=None)
    args = parser.parse_args()
    params = PRESETS[args.preset]
    report = readiness_summary(params)
    report['comparison'] = {
        'c4_projective_block2': estimate_c4_key(params, block_size=2, mode='projective', max_terms_per_block=1),
        'c6_projective_surface_block2': surface_counts(params, block_size=2).__dict__,
        'c7_coordinate_block1': estimate_c7_key(params, block_size=1, mode='coordinate'),
        'c7_coordinate_block2': estimate_c7_key(params, block_size=2, mode='coordinate'),
        'interpretation': 'C7 coordinate uses more compaction terms than C4 projective but removes the full projective weight-3 relation surface from the main security candidate.',
    }
    if args.json_output:
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    print(json.dumps(report, indent=2, sort_keys=True, default=str))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Compatibility wrapper for C7 screened-basis diagnostics.

For the final C7 package, the maintained diagnostic is run_c7_basis_screen.py.
This wrapper keeps older command names working while using the fast C7 basis
screen and readiness estimators.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.c7_relation_resistant import estimate_c7_key, readiness_summary
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser(description="Fast C7 screened-basis/readiness summary")
    parser.add_argument("--preset", default="c7_standard_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=1)
    parser.add_argument("--mode", default="coordinate", choices=["coordinate", "screened-random"])
    parser.add_argument("--entries-per-block", type=int, default=None)
    parser.add_argument("--relation-screen-weight", type=int, default=4)
    parser.add_argument("--out-prefix", default="docs/generated/c7_screened")
    # Accepted for backward compatibility; intentionally ignored by the fast wrapper.
    parser.add_argument("--target-size", type=int, default=None)
    parser.add_argument("--min-relation-weight", type=int, default=None)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--seed", type=int, default=717)
    args = parser.parse_args()
    params = PRESETS[args.preset]
    report = {
        "readiness": readiness_summary(params),
        "key_estimate": estimate_c7_key(
            params,
            block_size=args.block_size,
            mode=args.mode,
            entries_per_block=args.entries_per_block,
            relation_screen_weight=args.relation_screen_weight,
        ),
        "note": "Fast wrapper. Use run_c7_basis_screen.py for sampled basis details and run_c7_arithmetic_suite.py for operation tests.",
    }
    out_prefix = Path(args.out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    out_prefix.with_suffix(".json").write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    out_prefix.with_suffix(".txt").write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()

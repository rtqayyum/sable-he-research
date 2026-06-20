#!/usr/bin/env python3
"""Run symbolic SABLE-vs-TFHE/FHEW proxy comparisons."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.baseline import PROFILES, compare_profile, format_comparison
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="toy_depth2", choices=sorted(PRESETS))
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--profile", default="degree4_tree", choices=sorted(PROFILES))
    args = parser.parse_args()
    profiles = PROFILES.values() if args.all else [PROFILES[args.profile]]
    first = True
    for profile in profiles:
        if not first:
            print("\n" + "-" * 72 + "\n")
        first = False
        print(format_comparison(compare_profile(PRESETS[args.preset], profile)))


if __name__ == "__main__":
    main()

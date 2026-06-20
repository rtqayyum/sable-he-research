#!/usr/bin/env python3
"""Run the SABLE-HE heuristic attack estimator for a preset."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.attack_estimator import estimate_params, format_params_estimate
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="prototype_medium", choices=sorted(PRESETS))
    args = parser.parse_args()
    print(format_params_estimate(estimate_params(PRESETS[args.preset])))


if __name__ == "__main__":
    main()

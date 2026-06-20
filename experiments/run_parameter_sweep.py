#!/usr/bin/env python3
"""Print estimator summaries for built-in presets."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.estimator import estimate, format_estimate
from sable.params import PRESETS


def main() -> None:
    for preset_name in ["toy_clean", "toy_noisy", "toy_depth2", "prototype_medium"]:
        for depth in ([0, 1] if preset_name != "toy_depth2" else [0, 1, 2]):
            print("=" * 80)
            print(format_estimate(estimate(PRESETS[preset_name], depth=depth, additions=1)))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Sweep built-in presets through correctness and attack-screen estimators."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.attack_estimator import estimate_params
from sable.estimator import estimate
from sable.params import PRESETS


def main() -> None:
    print("preset,depth,correctness_failure_bound,best_attack_screen_bits,instance_statuses,warnings")
    for name, params in PRESETS.items():
        atk = estimate_params(params)
        best = atk["best_overall_feasible_log2_work"]
        statuses = "|".join(item["status"] for item in atk["instances"])
        for depth in (0, 1, 2):
            est = estimate(params, depth=depth, additions=1)
            warnings = " | ".join(est["warnings"])
            best_s = "n/a" if best is None else f"{best:.2f}"
            print(
                f"{name},{depth},{est['final_replica_failure_bound']:.6g},"
                f"{best_s},{statuses},{warnings}"
            )


if __name__ == "__main__":
    main()

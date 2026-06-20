#!/usr/bin/env python3
"""Run the SABLE-HE attack-screening estimator over built-in presets."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sable.attack_estimator import estimate_params, format_params_estimate
from sable.params import PRESETS


def flatten_rows(est: dict) -> list[dict]:
    rows = []
    preset = est["params"]["name"]
    for inst in est["instances"]:
        base = {
            "preset": preset,
            "instance": inst["instance"]["name"],
            "q": inst["instance"]["q"],
            "dimension": inst["instance"]["dimension"],
            "samples": inst["instance"]["samples"],
            "eta": inst["instance"]["eta"],
            "row_weight": inst["instance"]["row_weight"],
            "best_feasible_log2_work": inst["best_feasible_log2_work"],
            "status": inst["status"],
            "warnings": "; ".join(inst["warnings"]),
        }
        for attack in inst["attacks"]:
            row = dict(base)
            row.update({
                "attack": attack["name"],
                "log2_work": attack["log2_work"],
                "log2_memory": attack["log2_memory"],
                "feasible": attack["feasible_with_available_samples"],
                "model": attack["model"],
                "attack_note": "; ".join(attack["notes"]),
            })
            rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--presets", nargs="*", default=sorted(PRESETS), choices=sorted(PRESETS))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--csv", type=Path, default=None)
    args = parser.parse_args()

    estimates = [estimate_params(PRESETS[name]) for name in args.presets]
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        rows: list[dict] = []
        for est in estimates:
            rows.extend(flatten_rows(est))
        with args.csv.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    if args.json:
        print(json.dumps(estimates, indent=2))
    else:
        for est in estimates:
            print("=" * 88)
            print(format_params_estimate(est))


if __name__ == "__main__":
    main()

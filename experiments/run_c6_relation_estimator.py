"""Run C6 relation-surface screens for selected SABLE presets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sable.c6_relation_estimator import estimate_c6_relations, format_c6_report
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser(description="Run C6 relation-surface screens")
    parser.add_argument("--preset", action="append", choices=sorted(PRESETS), help="preset to evaluate; may repeat")
    parser.add_argument("--out-dir", default="docs/generated")
    parser.add_argument("--target-bits", type=float, default=128.0)
    args = parser.parse_args()
    presets = args.preset or ["c4_projective_toy_noisy", "c2_design_smallq", "prototype_medium"]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    for name in presets:
        report = estimate_c6_relations(PRESETS[name], target_bits=args.target_bits)
        summaries.append(report.to_jsonable())
        (out_dir / f"c6_relation_{name}.json").write_text(json.dumps(report.to_jsonable(), indent=2) + "\n", encoding="utf-8")
        (out_dir / f"c6_relation_{name}.txt").write_text(format_c6_report(report) + "\n", encoding="utf-8")
        print(format_c6_report(report))
        print("\n" + "=" * 78 + "\n")
    (out_dir / "c6_relation_summary.json").write_text(json.dumps(summaries, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

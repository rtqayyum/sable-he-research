"""Small C6 grid over C4 block size and CLPN noise.

The grid is intentionally compact.  It is a design screen showing how quickly
C4 projective relation surfaces become problematic when block_size >= 2.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
from pathlib import Path

from sable.c6_relation_estimator import estimate_c6_relations
from sable.params import PRESETS, SableParams


def main() -> None:
    parser = argparse.ArgumentParser(description="Run compact C6 parameter grid")
    parser.add_argument("--base", default="c2_design_smallq", choices=sorted(PRESETS))
    parser.add_argument("--out", default="docs/generated/c6_parameter_grid.csv")
    parser.add_argument("--target-bits", type=float, default=128.0)
    args = parser.parse_args()
    base = PRESETS[args.base]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for block_size in [1, 2, 3, 4]:
        for eta_c in [2**-18, 2**-16, 2**-14, 2**-12, 0.001, 0.005, 0.01, 0.02, 0.05]:
            p = SableParams(**{**dataclasses.asdict(base), "name": f"{base.name}_ell{block_size}_eta{eta_c:g}", "eta_c": eta_c, "c2_block_size": block_size})
            report = estimate_c6_relations(p, target_bits=args.target_bits, include_raw_relation_screen=False)
            counts = report.counts
            rows.append(
                {
                    "base": base.name,
                    "q": p.q,
                    "N": p.N,
                    "n_c": p.n_c,
                    "m_c": p.m_c,
                    "block_size": block_size,
                    "eta_c": eta_c,
                    "c4_entries": counts.c4_projective_entries,
                    "row_difference_samples": counts.row_difference_samples,
                    "rank_capped_relation_rows": counts.rank_capped_relation_rows,
                    "weight3_relation_rows_raw": counts.raw_weight3_relation_rows,
                    "weight3_noise": counts.weight3_relation_noise,
                    "min_bits": report.minimum_screen_bits,
                    "verdict": report.verdict,
                    "num_blockers": len(report.blockers),
                }
            )
    fieldnames = list(rows[0].keys()) if rows else []
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {out} with {len(rows)} rows")


if __name__ == "__main__":
    main()

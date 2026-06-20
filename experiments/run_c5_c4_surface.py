"""Run C5 C4-projective public-surface estimator."""

from __future__ import annotations

import argparse
from pathlib import Path

from sable.c5_c4_surface import estimate_c4_surface, format_surface_report
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="c4_projective_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--text-out", type=Path, default=None)
    args = parser.parse_args()
    report = estimate_c4_surface(PRESETS[args.preset], block_size=args.block_size)
    text = format_surface_report(report)
    print(text)
    if args.text_out:
        args.text_out.parent.mkdir(parents=True, exist_ok=True)
        args.text_out.write_text(text)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(report.to_json())


if __name__ == "__main__":
    main()

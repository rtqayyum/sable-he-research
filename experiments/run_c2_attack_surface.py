#!/usr/bin/env python3
"""Run the dedicated C2 public-sample attack-surface screen."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sable.c2_attack_surface import c2_attack_report, format_c2_attack_report, _jsonable
from sable.params import PRESETS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="c2_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--out", default=None)
    parser.add_argument("--json-out", default=None)
    args = parser.parse_args()
    report = c2_attack_report(PRESETS[args.preset], block_size=args.block_size, target_bits=args.target_bits)
    text = format_c2_attack_report(report)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(_jsonable(report), indent=2) + "\n")


if __name__ == "__main__":
    main()

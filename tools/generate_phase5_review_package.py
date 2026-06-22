#!/usr/bin/env python3
"""Generate a Phase 5 external-review package."""
from __future__ import annotations

import argparse
import json

from sable.standardization import write_review_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="sable_phase5_review_package")
    parser.add_argument("--preset", action="append", default=None)
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--target-bits", type=int, default=128)
    args = parser.parse_args()
    manifest = write_review_package(args.output, presets=args.preset, depth=args.depth, target_bits=args.target_bits)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate a SABLE-HE Phase 9 benchmark package."""
from __future__ import annotations

import argparse
from pathlib import Path

from sable.benchmarking import write_benchmark_package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="sable_phase9_benchmark_package")
    parser.add_argument("--preset", default="c7_standard_toy_clean")
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    paths = write_benchmark_package(Path(args.output), preset=args.preset, repetitions=args.repetitions)
    print(f"Wrote Phase 9 benchmark package to {args.output}")
    for key, path in paths.items():
        print(f"  {key}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

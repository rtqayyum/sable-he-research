#!/usr/bin/env python
"""Write the Phase 7 candidate parameter package."""

from __future__ import annotations

import argparse
import json

from sable.parameter_sets import write_parameter_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="sable_phase7_parameter_package")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    manifest = write_parameter_package(args.output)
    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(f"wrote {manifest['output']} with {manifest['candidate_count']} candidates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

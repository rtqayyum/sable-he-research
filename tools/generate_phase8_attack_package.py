#!/usr/bin/env python3
from __future__ import annotations

import argparse
from sable.attack_estimators_phase8 import write_attack_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="sable_phase8_attack_package")
    parser.add_argument("--candidate", action="append")
    args = parser.parse_args()
    manifest = write_attack_package(args.output, names=args.candidate)
    print(f"wrote {args.output}")
    print("files:")
    for f in manifest["files"]:
        print(f"  - {f}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

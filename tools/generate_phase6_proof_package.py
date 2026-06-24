#!/usr/bin/env python3
"""Generate a SABLE-HE formal proof-strengthening package."""
from __future__ import annotations
import argparse
from sable.proofs import write_proof_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="sable_proof_package")
    parser.add_argument("--preset", default="c7_standard_toy_noisy")
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--additions", type=int, default=1)
    parser.add_argument("--target-bits", type=int, default=128)
    parser.add_argument("--fl-clients", type=int, default=100)
    parser.add_argument("--model-length", type=int, default=100)
    args = parser.parse_args()
    result = write_proof_package(**vars(args))
    print(f"wrote {result['output']} files={len(result['files'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

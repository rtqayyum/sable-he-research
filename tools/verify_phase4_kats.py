#!/usr/bin/env python3
"""Verify a public Phase 4 known-answer vector directory."""
from __future__ import annotations

import argparse
import json

from sable import phase4


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SABLE-HE Phase 4 KAT bundle")
    parser.add_argument("path", nargs="?", default="vectors/phase4")
    parser.add_argument("--vectors-dir", dest="path", help="alias for path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = phase4.verify_kat_bundle(args.path)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"KAT verification status={result['status']} path={args.path}")
        for error in result.get("errors", []):
            print(f"  - {error}")
    return 0 if result.get("status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

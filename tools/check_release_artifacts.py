#!/usr/bin/env python3
"""Run the Phase 4 public release-artifact check."""
from __future__ import annotations

import argparse
import json

from sable import phase4


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SABLE-HE Phase 4 release checks")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--root", dest="path", help="alias for path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = phase4.release_artifact_check(args.path)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(f"release check status={result['status']} version={result['version']}")
        if result.get("missing_workflows"):
            print("missing workflows:")
            for item in result["missing_workflows"]:
                print(f"  - {item}")
    return 0 if result.get("status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

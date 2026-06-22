#!/usr/bin/env python3
"""Check that a public source tree excludes private research artifacts."""
from __future__ import annotations

import argparse
import json

from sable import phase4


def main() -> int:
    parser = argparse.ArgumentParser(description="Check public repository hygiene")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--root", dest="path", help="alias for path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = phase4.public_repo_hygiene(args.path)
    payload = report.to_jsonable()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"public repository hygiene status={report.status} scanned_files={report.scanned_files}")
        for finding in report.findings[:50]:
            print(f"  - {finding.severity}: {finding.path}: {finding.reason}")
    return 0 if report.status == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

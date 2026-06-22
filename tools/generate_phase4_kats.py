#!/usr/bin/env python3
"""Generate public Phase 4 known-answer test vectors."""
from __future__ import annotations

import argparse
import json

from sable import phase4


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SABLE-HE Phase 4 KAT bundle")
    parser.add_argument("--out", "--output", "--output-dir", dest="out", default="vectors/phase4")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    manifest = phase4.write_kat_bundle(args.out)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"wrote Phase 4 KAT bundle to {args.out}")
        print(f"status={manifest['status']} files={len(manifest['files'])}")
    return 0 if manifest.get("status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

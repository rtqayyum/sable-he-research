#!/usr/bin/env python3
"""Generate a Phase 10 compaction-theory review package."""

from __future__ import annotations

import argparse
import json

from sable.compaction_theory import write_compaction_package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="sable_phase10_compaction_package")
    parser.add_argument("--q", type=int, default=31)
    parser.add_argument("--n", type=int, default=512)
    parser.add_argument("--block-width", type=int, default=2)
    parser.add_argument("--m-c", type=int, default=192)
    parser.add_argument("--eta-c", type=float, default=2 ** -12)
    parser.add_argument("--max-relation-weight", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    manifest = write_compaction_package(
        args.output,
        q=args.q,
        n=args.n,
        block_width=args.block_width,
        m_c=args.m_c,
        eta_c=args.eta_c,
        max_relation_weight=args.max_relation_weight,
    )
    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(f"wrote {args.output}")
        for item in manifest["files"]:
            print(f"  - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

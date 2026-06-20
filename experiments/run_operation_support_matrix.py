#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from sable.operation_support import rows_as_dicts, markdown_table


def main() -> None:
    p = argparse.ArgumentParser(description='Emit operation-support comparison matrix')
    p.add_argument('--md-out', type=Path, default=None)
    p.add_argument('--csv-out', type=Path, default=None)
    p.add_argument('--json-out', type=Path, default=None)
    args = p.parse_args()
    rows = rows_as_dicts()
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(markdown_table() + '\n')
    if args.csv_out:
        args.csv_out.parent.mkdir(parents=True, exist_ok=True)
        with args.csv_out.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader(); writer.writerows(rows)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(rows, indent=2))
    print(markdown_table())


if __name__ == '__main__':
    main()

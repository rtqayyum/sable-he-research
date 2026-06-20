#!/usr/bin/env python3
"""Print SABLE-C8 readiness gates.

This script is intentionally strict. It distinguishes research readiness from
production/certification readiness so that release artifacts do not accidentally
claim more than the evidence supports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

GATES = [
    {
        "gate": "research_artifact",
        "status": "green",
        "meaning": "construction, paper, prototype, tests, and negative-result trail are present",
    },
    {
        "gate": "internal_validation",
        "status": "green",
        "meaning": "toy correctness, arithmetic, estimators, and relation screens are automated",
    },
    {
        "gate": "audit_package",
        "status": "green",
        "meaning": "ready to send to independent cryptanalysts with limitations disclosed",
    },
    {
        "gate": "production_cryptography",
        "status": "red",
        "meaning": "requires independent cryptanalysis, hardened implementation, side-channel review, audit, and stable parameters",
    },
    {
        "gate": "certified_secure_parameters",
        "status": "red",
        "meaning": "requires externally reviewed parameter security and attack-cost estimates",
    },
    {
        "gate": "standardization_ready",
        "status": "amber",
        "meaning": "submission materials exist in draft form, but parameters and external cryptanalysis are not frozen",
    },
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--write", type=Path, help="write JSON status to a file")
    args = parser.parse_args()
    payload = {"project": "SABLE-HE-C8", "gates": GATES}
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for gate in GATES:
            print(f"{gate['status'].upper():5s}  {gate['gate']}: {gate['meaning']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

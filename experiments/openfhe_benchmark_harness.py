
#!/usr/bin/env python3
"""Optional OpenFHE benchmark harness placeholder.

The validation package does not vendor OpenFHE.  This script is a scaffold
for the next external benchmarking step.  Install the official OpenFHE
Python wrapper in a separate environment, then replace the TODO sections
with BFV/BGV/FHEW workloads matching experiments/run_baseline_model.py.
"""

from __future__ import annotations


def main() -> None:
    try:
        import openfhe  # type: ignore  # noqa: F401
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            'OpenFHE Python wrapper is not installed. Install it separately and then implement concrete workloads.\n'
            f'Import error: {exc}'
        )
    raise SystemExit('OpenFHE detected. TODO: implement BFV/BGV/FHEW workloads from the baseline model table.')


if __name__ == '__main__':
    main()

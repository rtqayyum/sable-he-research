# Phase 7 build and test report

Version: `0.8.0`

Phase 7 adds candidate 128/192/256-bit parameter-set tooling for external cryptanalysis and paper review.

## Validation performed

- Full pytest suite: passed (`143` tests in this working package).
- CLI smoke tests:
  - `sable-he parameter-framework-info`
  - `sable-he candidate-parameters`
  - `sable-he parameter-report --candidate sable_cat1_depth1_review`
  - `sable-he parameter-package --output ...`
- Public repository hygiene check: passed before build artifacts were generated.
- Release check: passed before build artifacts were generated.
- Wheel smoke test in a fresh virtual environment: passed.

## Important limitation

The bundled candidate rows are **not certified parameter sets**. They are concrete review templates intended to support independent sparse-LPN, q-ary-LPN, ISD, and BKW cryptanalysis.

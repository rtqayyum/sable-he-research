# Release notes: v0.9 C7 READY

This release makes C7 the conservative default research candidate.

## Added

- `src/sable/c7_relation_resistant.py`
- `experiments/run_c7_arithmetic_suite.py`
- `experiments/run_c7_basis_screen.py`
- `experiments/run_c7_compare_baselines.py`
- `experiments/run_c7_readiness.py`
- `tests/test_c7_relation_resistant.py`
- `docs/c7_relation_resistant_design.md`
- `docs/c7_final_readiness_report.md`
- C7 appendix in the LaTeX manuscript

## Validation

- Full pytest suite: 95 passed.
- C7 arithmetic suite: 20 operation families, 60 toy-clean trials, 0 failures.
- Baseline comparison: operation-count/proxy comparison against TFHE/FHEW, BFV/BGV, and CKKS-style families.

## Research status

Ready as a research prototype and manuscript package.  Not ready for production deployment or certified security claims.

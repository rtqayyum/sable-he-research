# SABLE-HE v0.6: C4 projective additive-basis compaction

This release adds C4 projective additive-basis compaction.

## New files

- `src/sable/additive_basis.py`
- `src/sable/clpn_c4_basis.py`
- `src/sable/c4_estimator.py`
- `tests/test_additive_basis_c4.py`
- `tests/test_c4_compactor.py`
- `tests/test_c4_estimator.py`
- `experiments/run_c4_coverage.py`
- `experiments/run_c4_compaction_correctness.py`
- `experiments/run_c4_v123_comparison.py`
- `docs/c4_projective_design.md`
- `docs/validation_report_c4.md`
- `paper/sable_he_latex/appendices/h_c4_projective_basis.tex`

## Validation

`59 passed` under pytest.

## Main result

For a block of width `b` over `F_q`, C4 uses `(q^b - 1)/(q - 1)` projective entries instead of the C2/C3 full dictionary size `q^b - 1`, while preserving one CLPN compaction term per active block.

## Status

Research validation prototype only. Parameters are not certified secure.

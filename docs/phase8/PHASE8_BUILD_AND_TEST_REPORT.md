# Phase 8 build and test report

Phase 8 adds a strengthened internal LPN/ISD/BKW estimator layer for SABLE-HE candidate parameter review.

## Added modules

- `sable.lpn_estimator`
- `sable.lpn_estimators`
- `sable.attack_estimators_phase8`
- `sable.advanced_attacks`

## Main CLI commands

```bash
sable-he lpn-estimator-info
sable-he lpn-attack-report --candidate sable_cat1_depth1_review
sable-he lpn-estimator-package --output phase8_lpn_package
sable-he attack-estimator-info
sable-he attack-grid
sable-he attack-estimate --candidate sable_cat1_depth1_review
sable-he attack-package --output phase8_attack_package
```

## Validation status

- Unit tests collected: 158
- Unit tests passed: 158
- Wheel smoke test: passed
- LPN estimator package generation: passed
- Attack-estimator package generation: passed
- Clean ZIP hygiene: excludes build artifacts, PDFs, LaTeX sources, caches, and `dist/`

## Scope statement

The Phase 8 estimators are internal screening tools. They are useful for manuscript preparation and reviewer packages, but they are not certified parameter estimates and do not replace independent LPN, q-ary-LPN, ISD, or BKW cryptanalysis.

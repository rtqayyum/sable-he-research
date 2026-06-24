# Phase 7: candidate parameter-set framework

Phase 7 introduces concrete 128/192/256-bit review templates for SABLE-HE.  These templates are **not certified parameter sets**.  They are structured artifacts for reviewers: each template records correctness budgets, public sample counts, first-pass attack screens, and key-size implications.

The framework is designed to support a top-venue paper by making parameter selection explicit rather than informal.  A parameter set should only be promoted from candidate to recommended after external sparse-LPN, q-ary-LPN, ISD, and BKW review.

## Included commands

```bash
sable-he parameter-framework-info
sable-he parameter-candidates
sable-he parameter-report --candidate sable_cat1_depth1_review
sable-he parameter-package --output sable_parameter_package
```

## Interpretation

A candidate that passes the internal screen has only passed the bundled sanity checks.  It has not survived independent cryptanalysis, constant-time implementation review, or standardization review.

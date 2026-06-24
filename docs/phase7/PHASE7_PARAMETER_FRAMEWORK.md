# Phase 7: candidate parameter-set framework

Phase 7 adds concrete 128/192/256-bit target parameter templates for SABLE-HE.  The purpose is to move from qualitative statements such as "we need secure parameters" to reproducible tables that reviewers can inspect.

The bundled parameter rows are **candidate review templates**, not certified secure parameter sets.  They are intended for external cryptanalysis, paper appendices, and benchmark planning.

## Scope

Phase 7 provides:

- category-I/III/V-style target rows;
- correctness and failure-budget accounting;
- public sample-surface accounting;
- first-pass clean-subset, Prange/ISD, BKW, and sparse-row screens through the existing estimator stack;
- JSON, CSV, and Markdown review-package generation.

## Non-goals

Phase 7 does not provide:

- NIST/FIPS validation;
- certified SABLE-HE parameters;
- independent cryptanalysis;
- optimized production parameters;
- proof that SABLE-HE beats lattice HE in performance.

## CLI

```bash
sable-he parameter-framework-info
sable-he candidate-parameters
sable-he parameter-report --candidate sable_cat1_depth1_review
sable-he parameter-package --output sable_phase7_parameter_package
```

## Interpretation

A candidate row may have internal blockers, especially large key-size notes.  That is expected.  The goal is to expose bottlenecks honestly before the final paper and before inviting external review.

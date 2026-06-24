# Phase 8: strengthened LPN/ISD/BKW attack-estimator framework

Phase 8 adds reproducible screening tools for the public noisy-linear-equation surfaces exposed by SABLE-HE candidate parameters.  The goal is to strengthen the manuscript and review package before external cryptanalysis.

The estimator covers:

- sparse q-ary LPN expansion-key surfaces;
- dense q-ary LPN/code compaction-key surfaces;
- same-entry CLPN row-difference surfaces;
- deployment-dependent input-ciphertext accumulation surfaces;
- clean-subset/low-noise screens;
- Prange-style ISD screens;
- Stern/Dumer-style heuristic ISD improvement screens;
- q-ary block-BKW scans;
- row-entropy and birthday-collision diagnostics;
- generic exhaustive-secret bounds and conservative quantum proxies.

The estimator is not a certified security estimator and is not a substitute for expert sparse-LPN, q-ary-LPN, ISD, and BKW cryptanalysis.

## CLI

```bash
sable-he attack-estimator-info
sable-he attack-surfaces --candidate sable_cat1_depth1_review
sable-he attack-grid
sable-he attack-estimate --candidate sable_cat1_depth1_review
sable-he attack-package --output sable_phase8_attack_package
```

## Recommended paper wording

> Candidate parameter rows are evaluated using bundled clean-subset, ISD, q-ary block-BKW, relation-surface, and row-entropy screening tools. These screens are intended to expose weak settings before external review; they do not certify concrete security levels.

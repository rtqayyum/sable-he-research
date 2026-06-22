# Phase 3: Independent Cryptanalysis Package

Phase 3 prepares SABLE-HE for external cryptanalysis. It does not certify security and does not make SABLE-HE production cryptography. It gives reviewers a reproducible bundle containing parameter values, public LPN/code surfaces, correctness estimates, relation screens, and reviewer questions.

## Commands

```bash
sable-he cryptanalysis-info --preset c7_standard_toy_noisy
sable-he cryptanalysis-info --preset c7_standard_toy_noisy --json
sable-he cryptanalysis-bundle --preset c7_standard_toy_noisy --output-dir review_bundle
```

## Review surfaces

The bundle reports expansion-key sparse q-ary LPN rows, compaction-key q-ary LPN/code rows, same-entry CLPN row differences, and input-ciphertext accumulation under a deployment model.

## Required external review

Independent reviewers should analyze BKW-family, information-set-decoding, low-noise, clean-subset, sparse-row, large-sample, and relation-surface attacks. Passing bundled screens only means the bundled first-pass screens did not reject a preset.

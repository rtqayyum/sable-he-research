# Phase 6: Formal proof strengthening

This release adds a reviewer-facing formal proof package for SABLE-HE. The goal is to make the paper's theorem layer precise enough for external cryptographic review without claiming certified secure parameters.

## What is included

- A formal secret-key IND-CPA game with public evaluation keys.
- Proof obligations for compact encryption, GSW scalar encryption, expansion, homomorphic evaluation, compaction, and IND-CPA security.
- A hybrid-argument ledger for compaction-key, expansion-key, oracle-output, and challenge-ciphertext replacement steps.
- A deployment-aware sample-count ledger.
- Proof-review questions for external cryptographers.
- CLI commands to generate JSON/Markdown proof packages.

## What is not claimed

This release does not provide independent cryptanalysis, certified parameter sets, CCA security, bootstrapping/full FHE, NIST/FIPS validation, or production cryptographic assurance.

## CLI

```bash
sable-he proof-info
sable-he security-game
sable-he proof-obligations
sable-he proof-ledger --preset c7_standard_toy_noisy --fl-clients 100 --model-length 100
sable-he proof-package --output sable_proof_package
```

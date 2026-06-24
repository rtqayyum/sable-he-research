# Phase 6: Stronger proof and security-reduction package

Phase 6 turns the SABLE-HE proof layer into a reproducible review artifact. It adds theorem catalogs, proof obligations, game-hop descriptions, sample-surface accounting, and correctness-bound exports.

This package does not certify concrete parameters. It supports a future full paper appendix, independent cryptanalysis, and external review.

```bash
sable-he proof-info
sable-he security-game
sable-he proof-obligations
sable-he proof-ledger --preset c7_standard_toy_noisy
sable-he proof-package --output proof_review_bundle
```

# Phase 5: Standardization and External Review Guide

SABLE-HE v0.6.0 prepares the public project for independent cryptanalysis and pre-standardization discussion.

The correct public claim is:

> SABLE-HE is a post-quantum code/LPN-based leveled homomorphic-encryption research implementation for low-depth encrypted computation and federated aggregation.

The release does **not** claim NIST, ISO, HE.org, FIPS 140-3, CAVP, or CMVP approval. It packages the information reviewers need to decide whether the construction, assumptions, parameters, and implementation direction are credible.

## Outputs

- `sable-he standardization-info`
- `sable-he standardization-readiness`
- `sable-he assumptions-spec`
- `sable-he parameter-template`
- `sable-he review-checklist`
- `sable-he review-package`

## Review boundary

SABLE-HE should be reviewed separately from standardized PQC wrappers. The PQC wrapper labels ML-KEM/ML-DSA/AES/SHA style functions, but SABLE-HE itself is a research HE component, not a validated module.

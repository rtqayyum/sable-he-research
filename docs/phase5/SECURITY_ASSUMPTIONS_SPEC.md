# Security Assumptions Specification

The public security discussion is organized around three boundaries.

## Sparse q-ary LPN

Used for compact input encryption and GSW-style expansion-key rows. Reviewers should analyze public sample counts, sparse-row distributions, low-noise regimes, and multi-sample attacks.

## q-ary code/LPN compaction

Used for relation-resistant coordinate compaction. Reviewers should analyze row-difference surfaces, code-decoding assumptions, and q-ary piling-up behavior.

## Standardized PQC wrapper boundary

Used for envelope/key-management labels. The included demo provider is non-secure and only for tests. Production deployments need reviewed implementations and, where required, validated symmetric/PQC modules.

# SABLE-HE v0.9 C7 Final Validation

This release is the final research-prototype checkpoint in the current sequence.

## Main change

C7 replaces full projective C4 compaction as the main security candidate. C6 showed that full projective blocks contain many weight-3 public relations. C7 therefore makes coordinate relation-resistant compaction the default and keeps screened-random additive masks as an experimental optimization.

## What is validated

- All prior C2/C3/C4/C5/C6 tests remain in the package.
- C7 coordinate compaction is implemented in `src/sable/c7_relation_resistant.py`.
- C7 arithmetic validation covers addition, subtraction, negation, scalar multiplication, constants, multiplication, squaring, affine combinations, dot products, polynomial evaluation, balanced products, quadratic forms, and Boolean gates encoded over `F_q`.
- Baseline comparison remains an operation-count/proxy comparison, not an optimized-library wall-clock claim.

## Test result

`95 passed`

## Final status

Ready to pause as a research prototype and manuscript package. Not ready for production, standards claims, or certified concrete security.

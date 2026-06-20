# SABLE-HE v0.7 C5 arithmetic and baseline package

This release adds the C5 validation layer.

## Added

- Full public arithmetic interface for expanded SABLE ciphertexts:
  addition, subtraction, negation, public scalar multiplication, public
  constants, multiplication, squaring, powers, affine combinations, dot
  products, polynomial evaluation, products, quadratic forms, and Boolean
  gates encoded over F_q.
- End-to-end C4 compaction tests for the arithmetic operation suite.
- C5 operation-count/proxy comparison against TFHE/FHEW-style Boolean
  evaluation, BFV/BGV exact arithmetic, and CKKS approximate arithmetic.
- C5 public-surface diagnostic for C4 projective compaction.

## Main conclusion

SABLE is a low-degree arithmetic HE candidate, not merely a multiplication
demo.  Multiplication is the nonlinear bottleneck.  Once public constants and
linear operations are included, the construction evaluates arbitrary bounded
low-degree polynomial circuits over F_q.

## Important caveat

The Python timings are validation-prototype timings only.  They should not be
compared directly with optimized OpenFHE, SEAL, Concrete, TFHE-rs, or similar
libraries.  The included comparison table is a workload/proxy table for fair
future benchmarking.

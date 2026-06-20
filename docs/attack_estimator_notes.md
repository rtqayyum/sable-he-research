
# SABLE-HE attack-screening estimator notes

This repository now includes a screening estimator in `src/sable/attacks.py`.
It is deliberately labelled a **screening estimator**, not a certified
sparse-LPN/q-ary-LPN security estimator.

## What it checks

1. **Clean-subset linear-solving risk.**  If LPN noise is very small, a
   random set of `n` public equations can be entirely noise-free with
   probability about `(1-eta)^n`.  The estimator reports the expected trial
   cost in bits.  This catches the main correctness/security tension in
   SABLE-HE: small noise improves homomorphic correctness but weakens LPN.

2. **Prange/ISD first-order screen.**  The estimator treats noisy equations
   as a random-code decoding instance and computes the classic information
   set success probability.  This is a first-order screen only; modern ISD
   variants require specialized tools.

3. **BKW-style screen.**  The estimator includes a coarse q-ary BKW cost
   model.  This should be replaced by a dedicated LPN estimator before any
   security claim.

4. **Sparse-row entropy.**  The estimator computes the entropy of the sparse
   row distribution, `log2(C(n,k)(q-1)^k)`, and warns about birthday-scale
   row collisions.

## Main finding

The original `toy_*` presets and the earlier `prototype_medium` preset are
not cryptographic.  In particular, the low-noise choices make clean-subset
attacks cheap.  This does not invalidate the algebraic construction, but it
means the next research question is parameter feasibility, not library API
design.

## Implication for the manuscript

The paper should explicitly state that practical depth beyond 1 is the main
open bottleneck.  A credible submission should include:

- a tuned sparse-LPN/q-ary-LPN estimator;
- independent cryptanalysis;
- parameter tables that jointly satisfy correctness and attack screens;
- measured comparisons against TFHE/FHEW for Boolean circuits and BFV/BGV
  for exact arithmetic.

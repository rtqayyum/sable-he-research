# SABLE-HE attack estimator model

This repository now includes `sable.security_estimator`, a heuristic attack-cost
estimator for the sparse-LPN and q-ary-LPN layers used in SABLE-HE.

The estimator is intentionally transparent. It is designed to reveal weak or
implausible parameter choices, not to certify security.

## Implemented checks

1. **Exhaustive secret search.** Baseline cost `q^n` for a secret in
   `F_q^n`.
2. **Prange-style information-set decoding.** Given `m` noisy equations,
   `n` unknowns, and expected error count `t = ceil(eta*m)`, estimate the
   cost of finding an error-free set of `n` equations by
   `C(m,n) / C(m-t,n)`, plus a dense linear-algebra term.
3. **Low-noise error-support search.** Enumerates error supports and q-ary
   error values. This is naive but flags parameter choices with tiny expected
   noise.
4. **BKW block scan.** Scans block size `b`; estimates table size `q^b` and
   final distinguishing sample complexity from the q-ary bias after repeated
   sample addition.
5. **Sparse-row sample-space diagnostics.** Computes the approximate number of
   possible sparse rows, `C(n,k)(q-1)^k`, and compares it against public rows
   using birthday-style margins.

## How to run

```bash
PYTHONPATH=src python -m sable.security_estimator --preset toy_noisy
PYTHONPATH=src python -m sable.security_estimator --preset prototype_medium --json
python experiments/run_attack_sweep.py
```

## Interpretation

The output line `Overall minimum attack cost` is the minimum over the coarse
models above. Treat it as a red-team sanity check, not as a security theorem.
A real paper needs a dedicated sparse-LPN/q-ary-LPN cryptanalysis section and,
ideally, independent review.

## Known gaps

- no coded-BKW implementation;
- no advanced non-binary ISD variants;
- no sparse-LPN-specific rank/collision exploit search;
- no quantum cost model beyond the classical estimates shown here;
- no calibration against a mature external estimator.

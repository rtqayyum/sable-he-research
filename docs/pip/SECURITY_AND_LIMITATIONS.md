# Security Status and Limitations

This package is a research prototype.

## What it is

- A runnable implementation of the SABLE-HE research candidate.
- A validation harness for sparse-LPN-style input encryption, GSW-style evaluation, and C7 relation-resistant compaction.
- A platform for experiments, estimates, and cryptanalysis discussion.

## What it is not

- Not production cryptography.
- Not a certified secure parameter set.
- Not constant-time hardened code.
- Not a standardization-ready implementation.
- Not suitable for protecting real user data.

## Why C7 is the default

Earlier C4 projective compaction reduced compaction terms but created abundant public low-weight relations. C6 relation screening flagged those surfaces. C7 therefore returns to coordinate relation-resistant compaction as the conservative default and keeps screened random masks only as experimental optimization.

## Parameter status

Toy presets are included for correctness tests. Larger presets are provided for estimator experiments and should not be interpreted as final security parameters.

## Before production consideration

A production path would require:

1. independent cryptanalysis;
2. stable parameters against sparse-LPN, q-ary-LPN, BKW-style, and decoding-style attacks;
3. hardened implementation in a systems language;
4. audited serialization format;
5. constant-time and side-channel review;
6. fuzzing and negative testing;
7. external benchmarks against established HE libraries;
8. third-party review of proofs and assumptions.

## Recommended usage boundary

Use this package for research, teaching, experiments, and reproducibility. Do not use it for sensitive data.

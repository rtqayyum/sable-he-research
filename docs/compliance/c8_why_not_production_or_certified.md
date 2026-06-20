# Why C7/C8 is not yet production cryptography, certified parameters, or standardization-ready

## 1. Production cryptography is an evidence standard, not a label

A cryptographic implementation becomes production-worthy only after a chain of
evidence exists. For SABLE-HE this chain must include:

1. public specification and reproducible implementation;
2. independent cryptanalysis of the assumptions, parameter sets, and evaluation keys;
3. hardened implementation with constant-time rules where secret-dependent behavior exists;
4. fuzzing and differential tests;
5. known-answer test vectors;
6. misuse-resistant public API;
7. side-channel analysis;
8. external benchmarks against mature libraries;
9. an external security audit;
10. deployment and key-management guidance.

The current package has items 1, partial 4, partial 5, and partial benchmarking
scaffolding. It does not have independent cryptanalysis, external audits,
side-channel hardening, or certified parameters.

## 2. A certified secure parameter set cannot be self-certified

A parameter set can be proposed by the designers, but it becomes credible only
after independent attack analysis. For SABLE, this means at least:

- sparse-LPN attack costing;
- q-ary LPN attack costing;
- large-sample evaluation-key analysis;
- low-noise/clean-subset attacks;
- BKW-style attacks;
- ISD/Prange-style attacks;
- sparse-secret and sparse-row structural attacks;
- relation surfaces from compaction keys;
- correctness failure analysis for target circuit classes.

The C6/C7 work already found and fixed a major public-relation issue in C4.
That is a good sign for the research process, but it is also proof that more
cryptanalysis is required before a security-grade parameter set can be claimed.

## 3. Standardization readiness requires a frozen target

A standardization-grade package normally needs:

- frozen algorithms;
- stable parameter sets;
- reference implementation;
- optimized implementation or performance model;
- test vectors;
- security proof document;
- cryptanalysis report;
- patent/IPR statement;
- comparison against existing systems;
- clear failure modes and domain restrictions;
- interoperability tests.

SABLE has a candidate algorithm and research prototype, but parameter security
and external performance comparisons are not stable yet.

## 4. Honest final wording

Correct wording:

> SABLE-HE-C7 is an audit-ready research candidate for code/LPN-based leveled
> homomorphic encryption over low-degree arithmetic circuits.

Incorrect wording:

> SABLE-HE is production-certified post-quantum homomorphic encryption.

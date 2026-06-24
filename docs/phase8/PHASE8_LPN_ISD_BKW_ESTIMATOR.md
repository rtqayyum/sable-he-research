# Phase 8: Strengthened LPN/ISD/BKW estimator

Phase 8 adds an internal, reproducible attack-estimation layer for SABLE-HE.
It separates public surfaces and evaluates several screening families:

- clean-subset low-noise linear solving;
- Prange information-set decoding;
- Stern/Lee-Brickell-style list-ISD proxy;
- Dumer/MMT-style optimistic ISD proxy;
- plain q-ary BKW proxy;
- coded-BKW/LF-style proxy;
- sparse-row collision entropy.

The estimator is intended for paper tables and external review. It is not a
certified parameter estimator and must not be described as independent
cryptanalysis.

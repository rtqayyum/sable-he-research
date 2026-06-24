# Attack model specification

This document records the Phase 8 screening model. All formulas are transparent and intentionally conservative.

## No-clean-subset screen

For an LPN-like system with dimension `n` and effective noise `eta`, the low-noise clean-subset screen uses

```text
bits ~= -n log2(1 - eta) + omega log2(n)
```

where `omega = 2.8` is a dense-linear-algebra exponent proxy. This screen detects parameter rows where correctness forces the LPN noise too low.

## Prange/ISD proxy

For `m` samples, dimension `n`, and expected error count `t = eta*m`, the Prange proxy uses

```text
log2 binom(m,n) - log2 binom(m-t,n) + omega log2(n).
```

It is a basic information-set-decoding screen, not a modern optimized ISD estimator.

## Stern/Dumer-style proxy

The Stern/Dumer row is a heuristic improvement over Prange, capped conservatively. It is included to prevent the manuscript from relying only on the weakest ISD model. Specialist review is required.

## q-ary block-BKW scan

The BKW scan searches over a small grid of block widths and levels. It estimates table-building cost and final-bias sample complexity from the q-ary symmetric-noise bias

```text
beta = |1 - q*eta/(q-1)|.
```

A row is marked sample-limited when the public sample surface appears too small for the selected BKW setting.

## Quantum proxy

The quantum numbers are conservative screening proxies, mainly halving generic/ISD-style exponents. They are not a formal quantum attack theorem.

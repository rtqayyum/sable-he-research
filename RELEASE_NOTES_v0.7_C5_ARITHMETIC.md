# SABLE-HE v0.7 C5 arithmetic validation and C4 surface screen

## Added

- High-level arithmetic API: `src/sable/operations.py`.
- C5 C4-projective public-surface estimator: `src/sable/c5_attack_estimator.py`.
- Operation support matrix: `src/sable/operation_support.py`.
- Arithmetic correctness tests for addition, subtraction, negation, scalar/plain operations, multiplication, square, powers, nonzero inverse/division, polynomial evaluation, and Boolean gates.
- Microbenchmark script: `benchmarks/benchmark_arithmetic.py`.
- Operation comparison outputs and C5 attack-surface outputs under `docs/`.
- Paper appendices for C5 arithmetic and public-surface screening.

## Important result

We are not working only on multiplication. Multiplication is the main nonlinear primitive, but the expanded GSW representation supports the whole bounded-depth arithmetic circuit model over `F_q`.

## Main limitation

Division and comparisons are not native. Division is only represented as nonzero finite-field inversion by exponentiation, which is expensive and unsuitable as a core primitive.

## Validation

The v0.7 package passes the expanded test suite and includes pure-Python toy microbenchmarks. External optimized libraries were not installed, so only support/proxy comparisons are included for OpenFHE, SEAL, and TFHE-rs.

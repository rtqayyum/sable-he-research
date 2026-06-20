# SABLE-HE v0.7: C5 operation coverage, public-surface diagnostics, and baseline proxies

This release extends the C4 projective-compaction validation package in three ways.

## 1. Arithmetic operation coverage

SABLE's native plaintext domain is the prime field F_q.  The expanded GSW-style representation now exposes a public arithmetic layer for:

- public constants: gamma * I_N;
- zero and one;
- addition and subtraction;
- negation;
- public scalar multiplication;
- public constant addition/subtraction;
- encrypted multiplication;
- square and public powers;
- affine combinations and public-coefficient dot products;
- low-degree polynomial evaluation;
- Boolean gates on bits embedded as 0/1 in F_q: AND, OR, XOR, NOT, NAND, NOR, XNOR, implication.

Nonzero field inversion and division can be expressed by Fermat exponentiation, but this is expensive and undefined at zero. Integer comparison/order is not native.

## 2. C5 C4 public-surface diagnostics

The package adds C5 diagnostics for C4 projective compaction. C4 reduces public entries relative to C2/C3 full dictionaries, but projective blocks of width at least two have many low-weight linear relations. The C5 screen quantifies public CLPN rows, dense public field elements, projective relation surfaces, and rough compaction noise bounds.

These screens are red-flag diagnostics only. They do not certify sparse-LPN or q-ary-LPN security.

## 3. Baseline comparison proxies

The package now separates:

- measured pure-Python SABLE prototype timings on toy parameters;
- symbolic operation-count proxies for TFHE/FHEW, BFV/BGV, and CKKS-style baselines;
- operation support matrix describing which family best matches each workload.

The current validation environment does not run optimized OpenFHE, SEAL, or TFHE-rs wall-clock benchmarks. Do not interpret the pure-Python SABLE timings as speed comparisons against optimized libraries.

## Validation

The v0.7 test suite passes:

```text
83 passed
```

Generated validation outputs are in `docs/` and `docs/generated/`.

# SABLE-HE v0.7 C5 final summary

## What C5 adds

C5 answers the operation-scope question directly: SABLE-HE is not a multiplication-only candidate.  In the expanded GSW-style representation it supports the native low-degree arithmetic interface over `F_q`:

- public constants via `beta I`;
- zero and one;
- encrypted addition and subtraction;
- negation;
- public scalar multiplication;
- public-constant addition/subtraction;
- encrypted multiplication;
- squaring;
- public powers by square-and-multiply;
- affine combinations and dot products with public coefficients;
- polynomial evaluation by Horner's rule;
- balanced products and quadratic forms;
- Boolean gates on bits encoded as `0/1`: NOT, AND, OR, XOR, NAND, NOR, XNOR, and implication.

Encrypted division, comparison, sign, min/max, sorting, and branching are not native.  The prototype includes small-field Fermat inversion/division only as a validation tool, not as an efficient recommended primitive.

## Validation results

The package includes:

- `src/sable/arithmetic.py`: operation layer and Boolean polynomial gates;
- `experiments/run_c5_arithmetic_suite.py`: correctness/timing suite across arithmetic operations;
- `experiments/run_c5_compare_baselines.py`: operation-count/proxy comparison against TFHE/FHEW, BFV/BGV, and CKKS families;
- `experiments/run_c5_surface.py`: C4 projective public-surface diagnostic;
- new pytest coverage for arithmetic and C5 surface checks.

Latest full test result:

```text
83 passed
```

The arithmetic suite ran 5 trials for each tested operation on the clean C4 toy preset, and all operations succeeded.

## Existing-method comparison interpretation

The package does not fabricate optimized external timings.  The current comparison is a workload/proxy table:

- TFHE/FHEW: closest for Boolean gates, comparisons, and lookup/PBS-style workloads;
- BFV/BGV: closest for exact modular/integer arithmetic;
- CKKS: closest for approximate real/complex arithmetic, not exact finite-field output.

Actual wall-clock comparisons should be added only after compiling OpenFHE, SEAL, Concrete/TFHE-rs, or equivalent libraries under a fixed machine and security-policy setup.

## Main C5 conclusion

C4 projective compaction remains the best current SABLE compactor variant because it reduces C2/C3 dictionary entries by a factor of `q-1`.  However, C5 confirms that projective closure produces many weight-3 public linear relations.  That does not immediately break CLPN security, but it means the next required research step is a stronger large-sample q-ary-LPN/sparse-LPN estimator for the C4 public surface.

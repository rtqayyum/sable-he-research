# C5 arithmetic scope and benchmark status

## Scope

SABLE-HE is not limited to multiplication.  Multiplication is the hard
nonlinear operation, but the validation interface now tests the following
operations over the plaintext field F_q:

- addition: x + y;
- subtraction: x - y;
- negation: -x;
- public scalar multiplication: a x;
- public constants: x + c and c - x via c I_N;
- encrypted multiplication: x y;
- squaring: x^2;
- affine combinations and public-coefficient dot products;
- low-degree polynomial evaluation by Horner's rule;
- balanced products and quadratic forms;
- Boolean gates on bits encoded as 0/1: NOT, AND, OR, XOR, NAND, NOR, XNOR, implication.

Not native in the current construction: encrypted division, comparison,
sign, min/max, sorting, encrypted branching, table lookup, and arbitrary
bootstrapped evaluation.  These must be converted into bounded arithmetic or
Boolean circuits, and the supported depth/noise budget must then be checked.

## Benchmark status

The repository now includes two benchmark layers:

1. `experiments/run_c5_arithmetic_suite.py` measures the pure-Python
   SABLE validation prototype on the operation suite.
2. `experiments/run_c5_compare_baselines.py` emits an operation-count/proxy
   table for TFHE/FHEW-style Boolean evaluation, BFV/BGV exact arithmetic,
   and CKKS approximate arithmetic.

These are deliberately not claimed as optimized wall-clock comparisons.
The right future measured baselines are OpenFHE FHEW/TFHE for Boolean gates,
OpenFHE or Microsoft SEAL BFV/BGV for exact modular arithmetic, and CKKS
only for approximate real-valued workloads.

## Main C5 conclusion

C4 projective compaction improves key surface relative to full C2/C3 block
dictionaries, but C5 shows that projective closure creates many weight-3
public linear relations.  This does not break the design by itself, because
the entries are still noisy CLPN encryptions, but it is a large-sample
q-ary-LPN surface that must be analyzed before any security-grade parameter
claim.

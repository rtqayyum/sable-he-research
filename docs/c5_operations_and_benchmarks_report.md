# C5 arithmetic and benchmark report

## Operation support

SABLE-HE evaluates arithmetic circuits over the prime field F_q after compact ciphertexts are expanded to the GSW-style representation.  Multiplication is the nonlinear primitive, but the prototype is not limited to multiplication.  The C5 operation layer tests linear operations, public constants, multiplication, powers, polynomial evaluation, public dot products, and Boolean gates encoded as polynomials over bits in F_q.

Native operations:

- addition, subtraction, negation;
- public scalar multiplication;
- public constants via gamma * I_N;
- encrypted multiplication by sparse matrix multiplication;
- squaring, powers, polynomial evaluation;
- Boolean AND/OR/XOR/NOT/NAND/NOR/XNOR/implication on 0/1 plaintexts.

Boundary operations:

- nonzero inverse and division are algebraically possible through x^(q-2) but expensive and undefined at zero;
- equality-to-constant is possible through 1-(x-a)^(q-1) but high-depth for large q;
- integer comparison, ordering, min/max, and table lookup are not native and require Boolean encodings or a different HE family such as TFHE/FHEW-style lookup/bootstrapping.

## Tests

The arithmetic test suite uses the C4 projective compactor on toy-clean parameters and checks every operation against plaintext field arithmetic.  The latest run produced zero failures across all tested operations.  See:

- `docs/c5_arithmetic_suite_output.txt`
- `docs/c5_arithmetic_suite_output.json`
- `docs/generated/c5_arithmetic_suite.csv`

## Performance comparison policy

The package reports two kinds of data:

1. pure-Python SABLE prototype timings on toy parameters;
2. symbolic operation-count proxies for mature existing methods.

This is intentional. SABLE is a research prototype. OpenFHE, Microsoft SEAL, and TFHE-rs are optimized libraries written in C++/Rust and use mature parameter-selection, bootstrapping, and low-level arithmetic. Direct wall-clock comparison would be misleading unless those systems are installed and run on the same machine with comparable workloads and parameters.

## Baseline mapping

- TFHE/FHEW: closest baseline for Boolean gates, comparisons, table lookups, and programmable bootstrapping.
- BFV/BGV: closest exact arithmetic baseline for modular/integer arithmetic.
- CKKS: closest baseline for approximate real/complex arithmetic, not exact finite-field output.

See:

- `docs/operation_support_matrix.md`
- `docs/c5_baseline_comparison.json`
- `docs/generated/c5_baseline_comparison.csv`
- `docs/operation_benchmarks_v07.json`
- `docs/generated/operation_benchmarks_v07.csv`

## C5 public-surface result

C4 projective compaction reduces the number of public entries compared with C2/C3 full block dictionaries. For q=7 and block width 2, C4 uses 8 projective representatives per full block versus 48 nonzero dictionary entries in C2/C3. However, full projective blocks have many low-weight relations. The C5 screen therefore marks the projective surface as requiring dedicated q-ary-LPN analysis before any security-grade parameter claim.

See:

- `docs/c5_surface_output.json`
- `docs/c5_attack_estimator_output.json`

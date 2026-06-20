# SABLE-HE v0.7 C5 arithmetic validation report

## Scope

C5 broadens validation from multiplication-only tests to the full native field-arithmetic interface supported by the expanded GSW representation.

SABLE-C4 natively supports:

- public constants (`beta I` in the expanded representation);
- zero and one;
- encrypted addition and subtraction;
- negation;
- public scalar multiplication;
- public-constant addition/subtraction;
- encrypted multiplication;
- square;
- public powers by square-and-multiply;
- low-degree public polynomials;
- Boolean gates encoded as arithmetic polynomials over `F_q`.

Division is not a cheap native primitive. The prototype includes `inverse_nonzero(x)=x^(q-2)` and `x/y=x*y^(q-2)` for nonzero denominators in small prime fields only.

## Tests added

- `tests/test_operations_arithmetic_c5.py`
- `tests/test_c5_attack_estimator.py`

The arithmetic suite checks constants, linear operations, multiplication, oriented multiplication, powers, inverse, division, a mixed quadratic polynomial, and Boolean gates AND/OR/XOR/NOT/NAND/NOR/XNOR.

## Microbenchmark

The file `docs/arithmetic_microbench_c4_toy_clean.csv` records pure-Python toy-parameter timings. These timings validate the prototype and show relative costs inside our implementation; they are not optimized-library comparisons.

Summary from the latest run:

```text
zero             eval_med=   0.0245 ms  eval+compact+dec_med=   0.2154 ms  verified=True
one              eval_med=   0.0623 ms  eval+compact+dec_med=   0.4385 ms  verified=True
const_4          eval_med=   0.0618 ms  eval+compact+dec_med=   0.4338 ms  verified=True
add              eval_med=   0.0590 ms  eval+compact+dec_med=   0.9680 ms  verified=True
sub              eval_med=   0.0593 ms  eval+compact+dec_med=   1.0431 ms  verified=True
neg              eval_med=   0.0465 ms  eval+compact+dec_med=   0.7810 ms  verified=True
scalar_mul_4     eval_med=   0.0456 ms  eval+compact+dec_med=   0.7529 ms  verified=True
add_plain_6      eval_med=   0.1173 ms  eval+compact+dec_med=   0.8866 ms  verified=True
mul              eval_med=   0.1918 ms  eval+compact+dec_med=   1.3859 ms  verified=True
square           eval_med=   0.1910 ms  eval+compact+dec_med=   1.3349 ms  verified=True
pow3             eval_med=   0.5543 ms  eval+compact+dec_med=   1.8272 ms  verified=True
inverse_nonzero  eval_med=   1.0534 ms  eval+compact+dec_med=   2.4561 ms  verified=True
div_nonzero      eval_med=   1.5316 ms  eval+compact+dec_med=   3.0492 ms  verified=True
bool_not_1       eval_med=   0.1212 ms  eval+compact+dec_med=   0.6501 ms  verified=True
bool_and_10      eval_med=   0.1992 ms  eval+compact+dec_med=   1.2689 ms  verified=True
bool_or_10       eval_med=   0.3388 ms  eval+compact+dec_med=   1.2391 ms  verified=True
bool_xor_10      eval_med=   0.3899 ms  eval+compact+dec_med=   1.4047 ms  verified=True
```

## External comparison methodology

The operation-support matrix is in:

- `docs/operation_support_matrix.md`
- `docs/operation_support_matrix.csv`
- `docs/operation_support_matrix.json`

The comparison is deliberately split into:

- TFHE/FHEW-style Boolean and integer circuits;
- BFV/BGV exact modular arithmetic;
- CKKS approximate real arithmetic;
- SABLE-C4 finite-field, bounded-depth, code/LPN-based arithmetic.

The repository does not fabricate external wall-clock numbers. It includes scaffolding for future OpenFHE/TFHE-rs/SEAL experiments when those libraries are installed.

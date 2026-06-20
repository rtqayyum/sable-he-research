# SABLE-HE research package user guide

SABLE-HE is a pip-installable **research validation prototype** for the SABLE-HE candidate construction:

```text
sparse-LPN nonlinear homomorphic evaluation
+ q-ary code/LPN linear compaction
```

The package is designed for experiments, manuscript validation, arithmetic-operation tests, attack-surface screens, and benchmark planning. It is **not production cryptography** and the bundled presets are **not certified secure parameter sets**.

## 1. Installation

### Option A: install from the wheel

From the folder containing the built wheel:

```bash
python -m pip install dist/sable_he_research-0.1.0-py3-none-any.whl
```

### Option B: install from source

```bash
python -m pip install .
```

### Option C: editable research/development install

```bash
python -m pip install -e .[dev]
python -m pytest -q
```

The package uses the modern `pyproject.toml`/`src/` layout. The distribution name is:

```text
sable-he-research
```

The Python import package is:

```python
import sable
```

The command-line tool is:

```bash
sable-he
```

## 2. First CLI commands

List presets:

```bash
sable-he presets
```

Run a multiplication demo with C7 relation-resistant compaction:

```bash
sable-he demo --operation mul --x 3 --y 5 --preset c7_standard_toy_clean
```

Run a Boolean XOR demo over bits embedded into `F_q`:

```bash
sable-he demo --operation xor --x 1 --y 0 --preset c7_standard_toy_clean
```

Estimate correctness/size/security screens:

```bash
sable-he estimate --preset c7_standard_toy_noisy --depth 1 --additions 1
```

Run the C7 public-surface screen:

```bash
sable-he screen-c7 --preset c7_standard_toy_noisy
```

Print proxy comparisons against major HE families:

```bash
sable-he baselines --preset c7_standard_toy_noisy
```

JSON output is available on most commands:

```bash
sable-he demo --operation add --x 2 --y 4 --json
sable-he estimate --preset c7_standard_toy_noisy --json
```

## 3. Minimal Python API example

```python
from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable.operations import mul

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")

x = 3
y = 5
ctx = expand(kp, encrypt(kp, x, seed=1))
cty = expand(kp, encrypt(kp, y, seed=2))

ctxy = mul(ctx, cty)
out = decrypt_c7(kp, compact_c7(kp, ctxy))

assert out == (x * y) % params.q
print(out)
```

## 4. Arithmetic model

SABLE's native plaintext domain is a prime field:

```text
F_q
```

The package supports low-degree arithmetic circuits over `F_q`. Multiplication is the main nonlinear bottleneck, but the arithmetic layer supports much more than multiplication.

Supported operations include:

| Operation family | API |
|---|---|
| Addition | `sable.operations.add` |
| Subtraction | `sable.operations.sub` |
| Negation | `sable.operations.neg` |
| Public scalar multiplication | `sable.operations.scalar_mul` |
| Public constants | `sable.operations.const_like`, `zero_like`, `one_like` |
| Public constant addition/subtraction | `add_plain`, `sub_plain`, `plain_sub` |
| Multiplication | `mul` |
| Squaring | `square` |
| Public powers | `pow_plain` |
| Affine combinations | `affine_combination` |
| Dot products | `dot` |
| Polynomial evaluation | `poly_eval` |
| Products and balanced products | `product`, `balanced_product` |
| Quadratic forms | `quadratic_form` |
| Boolean gates over embedded bits | `gate_not`, `gate_and`, `gate_or`, `gate_xor`, `gate_nand`, `gate_nor`, `gate_xnor` |

Division is not native. Nonzero finite-field inversion can be expressed by exponentiation as `x^(q-2)`, but that is expensive and only appropriate for toy validation.

Comparison and ordering are also not native. Use Boolean-circuit encodings or future TFHE/FHEW-style comparison baselines for that workload.

## 5. C7 compaction modes

The current conservative main path is C7 coordinate relation-resistant compaction:

```python
kp = keygen_c7(params, seed=123, mode="coordinate")
ct_compact = compact_c7(kp, ct_evaluated)
out = decrypt_c7(kp, ct_compact)
```

Earlier C2/C3/C4 variants remain in the repository for reproducibility and negative-result documentation. C4 projective compaction is algebraically correct but was not kept as the main candidate because the C6 relation screen found abundant weight-3 public relation surfaces.

## 6. Parameters

Inspect presets:

```python
from sable.params import PRESETS
print(PRESETS.keys())
print(PRESETS["c7_standard_toy_clean"])
```

Toy presets are for algebraic tests only. Larger presets are feasibility and screening starting points, not certified security parameters.

A parameter object contains:

```text
q        prime plaintext modulus
n        sparse-LPN secret dimension
k        sparse row weight
eta      sparse-LPN noise rate
n_c      compaction secret dimension
m_c      compaction code length / rows
eta_c    compaction noise rate
replicas independent replicas for majority decoding
c2_block_size reused as a block-width parameter in later compactors
```

## 7. Estimators

The package includes several conservative screens. They are useful for rejecting weak candidates and finding bottlenecks, but they are not formal certification.

CLI:

```bash
sable-he estimate --preset c7_standard_toy_noisy --depth 1 --additions 1
sable-he screen-c7 --preset c7_standard_toy_noisy
```

Python:

```python
from sable.params import PRESETS
from sable.estimator import estimate, format_estimate

report = estimate(PRESETS["c7_standard_toy_noisy"], depth=1, additions=1)
print(format_estimate(report))
```

## 8. Baseline comparison guidance

The package includes proxy comparisons, not optimized external wall-clock benchmarks.

The fair comparison families are:

| Workload | Best baseline family |
|---|---|
| Boolean gates, comparisons, small lookup/function evaluation | TFHE/FHEW-style Boolean HE |
| Exact modular arithmetic | BFV/BGV |
| Approximate real arithmetic / ML inference | CKKS |
| Low-degree finite-field arithmetic with code/LPN assumption diversity | SABLE-HE candidate |

Use OpenFHE, Microsoft SEAL, Concrete/TFHE-rs, or equivalent tools for measured external benchmarks in the next phase.

## 9. Test suite

From a source checkout:

```bash
python -m pip install -e .[dev]
python -m pytest -q
```

The C8 package was prepared with the existing internal validation suite passing.

## 10. Safe-use notice

Do not use SABLE-HE to protect real data. The package is intended for:

- research validation;
- mathematical experiments;
- cryptanalysis preparation;
- manuscript reproducibility;
- educational demonstrations of the construction.

A production cryptography implementation would need independent cryptanalysis, stable parameters, constant-time/hardened implementation work, fuzzing, side-channel review, KAT vectors, external benchmarking, and professional audit.

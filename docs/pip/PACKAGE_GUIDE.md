# SABLE-HE pip Package Guide

This guide explains the full install-and-use flow for `sable-he-research`.

## 1. Install

From the unpacked project folder:

```bash
python -m pip install dist/sable_he_research-0.1.0-py3-none-any.whl
```

Or install directly from source:

```bash
python -m pip install .
```

Verify:

```bash
sable-he --version
sable-he info
sable-he self-test
```

## 2. Use from Python

```python
from sable import PRESETS, keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as ops

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123)

x = expand(kp, encrypt(kp, 3, seed=1))
y = expand(kp, encrypt(kp, 5, seed=2))

z = ops.mul(x, y)
answer = decrypt_c7(kp, compact_c7(kp, z))
print(answer)
```

## 3. Evaluate common operations

```python
ops.add(x, y)              # x + y
ops.sub(x, y)              # x - y
ops.neg(x)                 # -x
ops.scalar_mul(x, 3)       # 3x
ops.add_plain(x, 4)        # x + 4
ops.mul(x, y)              # xy
ops.square(x)              # x^2
ops.pow_plain(x, 3)        # x^3
ops.gate_not(x)            # 1-x for bit x
ops.gate_and(x, y)         # xy for bits
ops.gate_or(x, y)          # x+y-xy for bits
ops.gate_xor(x, y)         # x+y-2xy for bits
```

## 4. Use the CLI

```bash
sable-he demo --operation mul --x 3 --y 5
sable-he run xor --x 1 --y 0
sable-he quickstart
sable-he estimate --preset c7_standard_toy_clean --depth 1
sable-he compare --preset c7_standard_toy_clean
sable-he screen-c7 --preset c7_standard_toy_noisy
sable-he readiness
```

## 5. Run examples

```bash
python examples/quickstart.py
python examples/arithmetic_operations.py
python examples/boolean_gates.py
python examples/estimator_demo.py
```

## 6. Development workflow

```bash
python -m pip install -e ".[dev]"
pytest
```

Build artifacts:

```bash
python -m pip wheel . --no-deps --no-build-isolation -w dist
python - <<'PY'
import setuptools.build_meta as bm
print(bm.build_sdist('dist'))
PY
```

## 7. Security boundary

This is a research package. Toy presets show algebraic correctness. They do not provide a certified secure parameter set. Do not use this package to protect sensitive data.


## Federated-learning aggregation

See `docs/pip/FL_AGGREGATION.md` and `docs/fl/FEDERATED_LEARNING_GUIDE.md` for encrypted FedAvg, weighted aggregation, and tensor/model adapters.

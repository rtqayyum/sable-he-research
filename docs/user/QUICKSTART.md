# Quickstart

## Run the CLI demo

```bash
sable-he quickstart --x 3 --y 5
```

Expected output includes:

```text
operation: mul
observed=15 expected=15 passes=True
```

The default preset is `c7_standard_toy_clean`, which has zero noise and is suitable for deterministic algebra tests only.

## Run a Boolean gate

```bash
sable-he run xor --x 1 --y 0
sable-he run and --x 1 --y 1
sable-he run implies --x 1 --y 0
```

Boolean inputs must be encoded as `0` or `1` in the field.

## Run the estimator

```bash
sable-he estimate --preset c7_standard_toy_clean --depth 1
sable-he estimate --preset c7_design_smallq --depth 1 --json
```

The estimator reports correctness bounds, size proxies, and heuristic attack-screen information. These are screening tools, not certifications.

## Python API

```python
from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as A

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")

def enc(value, seed):
    return expand(kp, encrypt(kp, value, seed=seed))

x = enc(3, 1)
y = enc(5, 2)
z = A.add(A.mul(x, y), A.const_like(x, 4))
out = decrypt_c7(kp, compact_c7(kp, z))
assert out == (3 * 5 + 4) % params.q
```

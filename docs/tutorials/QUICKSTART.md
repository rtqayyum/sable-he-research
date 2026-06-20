# Quickstart tutorial

This tutorial runs one finite-field multiplication and one Boolean gate.

## Install

```bash
python -m pip install dist/sable_he_research-0.1.0-py3-none-any.whl
```

or from source:

```bash
python -m pip install .
```

## Multiplication over F_q

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

ctz = mul(ctx, cty)
z = decrypt_c7(kp, compact_c7(kp, ctz))

print(z)
assert z == (x * y) % params.q
```

## Boolean XOR over embedded bits

```python
from sable.operations import gate_xor

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=99, mode="coordinate")

a = 1
b = 0
cta = expand(kp, encrypt(kp, a, seed=3))
ctb = expand(kp, encrypt(kp, b, seed=4))

ctxor = gate_xor(cta, ctb)
out = decrypt_c7(kp, compact_c7(kp, ctxor))

print(out)
assert out == 1
```

## CLI equivalent

```bash
sable-he demo --operation mul --x 3 --y 5
sable-he demo --operation xor --x 1 --y 0
```

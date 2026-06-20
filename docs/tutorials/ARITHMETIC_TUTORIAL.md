# Arithmetic Tutorial

This example evaluates

```text
f(x, y) = x*y + 2*x - y + 4 mod q
```

```python
from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as A

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")

def enc(v, seed):
    return expand(kp, encrypt(kp, v, seed=seed))

x_plain, y_plain = 3, 5
x = enc(x_plain, 1)
y = enc(y_plain, 2)

term = A.add(A.mul(x, y), A.scalar_mul(x, 2))
term = A.sub(term, y)
term = A.add(term, A.const_like(x, 4))

out = decrypt_c7(kp, compact_c7(kp, term))
expected = (x_plain * y_plain + 2 * x_plain - y_plain + 4) % params.q
assert out == expected
```

# Boolean Gates Tutorial

Boolean bits are encoded as `0` or `1` in `F_q`.

```python
from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as A

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")

def enc_bit(v, seed):
    assert v in (0, 1)
    return expand(kp, encrypt(kp, v, seed=seed))

x = enc_bit(1, 1)
y = enc_bit(0, 2)

for name, ct in {
    "and": A.gate_and(x, y),
    "or": A.gate_or(x, y),
    "xor": A.gate_xor(x, y),
    "implies": A.gate_implies(x, y),
}.items():
    print(name, decrypt_c7(kp, compact_c7(kp, ct)))
```

"""Minimal encrypted multiplication demo for SABLE-HE Research."""

from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as A

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")

x, y = 3, 5
ctx = expand(kp, encrypt(kp, x, seed=1))
cty = expand(kp, encrypt(kp, y, seed=2))
ctz = A.mul(ctx, cty)
observed = decrypt_c7(kp, compact_c7(kp, ctz))
expected = (x * y) % params.q

print({"operation": "mul", "x": x, "y": y, "observed": observed, "expected": expected})
assert observed == expected

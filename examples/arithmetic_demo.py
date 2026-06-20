"""Evaluate f(x,y)=x*y + 2*x - y + 4 over F_q."""

from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as A

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")

def enc(v: int, seed: int):
    return expand(kp, encrypt(kp, v, seed=seed))

x_plain, y_plain = 3, 5
x = enc(x_plain, 1)
y = enc(y_plain, 2)

z = A.add(A.mul(x, y), A.scalar_mul(x, 2))
z = A.sub(z, y)
z = A.add(z, A.const_like(x, 4))

observed = decrypt_c7(kp, compact_c7(kp, z))
expected = (x_plain * y_plain + 2 * x_plain - y_plain + 4) % params.q

print({"observed": observed, "expected": expected})
assert observed == expected

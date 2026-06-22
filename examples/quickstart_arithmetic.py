from sable import PRESETS, keygen_sable, encrypt, expand, compact_sable, decrypt_sable
from sable import operations as ops

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_sable(params, seed=123, mode="coordinate")

x = expand(kp, encrypt(kp, 3, seed=1))
y = expand(kp, encrypt(kp, 5, seed=2))
z = ops.mul(x, y)

print(decrypt_sable(kp, compact_sable(kp, z)))

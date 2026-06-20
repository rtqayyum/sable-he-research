"""Minimal SABLE-HE encrypted arithmetic demo.

Run after installation:
    python examples/quickstart.py
"""

from sable import PRESETS, compact_c7, decrypt_c7, encrypt, expand, keygen_c7
from sable import operations as ops


def main() -> None:
    params = PRESETS["c7_standard_toy_clean"]
    kp = keygen_c7(params, seed=123)

    x_val, y_val = 3, 5
    x = expand(kp, encrypt(kp, x_val, seed=1))
    y = expand(kp, encrypt(kp, y_val, seed=2))

    z = ops.mul(x, y)
    out = decrypt_c7(kp, compact_c7(kp, z))
    expected = (x_val * y_val) % params.q

    print(f"q={params.q}")
    print(f"({x_val} * {y_val}) mod q = {expected}")
    print(f"decrypted result = {out}")
    assert out == expected


if __name__ == "__main__":
    main()

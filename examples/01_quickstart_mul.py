"""Minimal SABLE-HE multiplication example.

Run after installation:
    python examples/01_quickstart_mul.py
"""

from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable.operations import mul


def main() -> None:
    params = PRESETS["c7_standard_toy_clean"]
    kp = keygen_c7(params, seed=123, mode="coordinate")

    x, y = 3, 5
    ctx = expand(kp, encrypt(kp, x, seed=1))
    cty = expand(kp, encrypt(kp, y, seed=2))

    ctxy = mul(ctx, cty)
    out = decrypt_c7(kp, compact_c7(kp, ctxy))
    expected = (x * y) % params.q

    print({"operation": "mul", "x": x, "y": y, "expected": expected, "decrypted": out})
    assert out == expected


if __name__ == "__main__":
    main()

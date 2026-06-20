"""Run several encrypted arithmetic operations under toy parameters."""

from sable import PRESETS, compact_c7, decrypt_c7, encrypt, expand, keygen_c7
from sable import operations as ops


def dec(kp, ct):
    return decrypt_c7(kp, compact_c7(kp, ct))


def main() -> None:
    params = PRESETS["c7_standard_toy_clean"]
    kp = keygen_c7(params, seed=7)
    q = params.q
    x_val, y_val = 3, 5
    x = expand(kp, encrypt(kp, x_val, seed=8))
    y = expand(kp, encrypt(kp, y_val, seed=9))

    cases = {
        "add": (ops.add(x, y), (x_val + y_val) % q),
        "sub": (ops.sub(x, y), (x_val - y_val) % q),
        "neg": (ops.neg(x), (-x_val) % q),
        "scalar_mul_by_4": (ops.scalar_mul(x, 4), (4 * x_val) % q),
        "mul": (ops.mul(x, y), (x_val * y_val) % q),
        "square": (ops.square(x), (x_val * x_val) % q),
    }

    for name, (ct, expected) in cases.items():
        observed = dec(kp, ct)
        print(f"{name:16s} expected={expected} observed={observed}")
        assert observed == expected


if __name__ == "__main__":
    main()

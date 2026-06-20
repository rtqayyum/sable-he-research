"""Small arithmetic examples for the SABLE-HE research API."""

from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable.operations import add, sub, neg, scalar_mul, mul, square, add_plain


def dec(kp, ct):
    return decrypt_c7(kp, compact_c7(kp, ct))


def main() -> None:
    params = PRESETS["c7_standard_toy_clean"]
    q = params.q
    kp = keygen_c7(params, seed=321, mode="coordinate")

    x, y = 4, 6
    ctx = expand(kp, encrypt(kp, x, seed=1))
    cty = expand(kp, encrypt(kp, y, seed=2))

    checks = {
        "add": (dec(kp, add(ctx, cty)), (x + y) % q),
        "sub": (dec(kp, sub(ctx, cty)), (x - y) % q),
        "neg": (dec(kp, neg(ctx)), (-x) % q),
        "scalar_mul_3": (dec(kp, scalar_mul(ctx, 3)), (3 * x) % q),
        "add_plain_2": (dec(kp, add_plain(ctx, 2)), (x + 2) % q),
        "mul": (dec(kp, mul(ctx, cty)), (x * y) % q),
        "square": (dec(kp, square(ctx)), (x * x) % q),
    }

    for name, (got, expected) in checks.items():
        print(f"{name:<14} got={got} expected={expected}")
        assert got == expected


if __name__ == "__main__":
    main()

"""Boolean gates using bits embedded as 0/1 in F_q."""

from sable.params import PRESETS
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable.operations import gate_and, gate_or, gate_xor, gate_not, gate_nand, gate_nor, gate_xnor


def dec(kp, ct):
    return decrypt_c7(kp, compact_c7(kp, ct))


def main() -> None:
    params = PRESETS["c7_standard_toy_clean"]
    kp = keygen_c7(params, seed=456, mode="coordinate")

    a, b = 1, 0
    cta = expand(kp, encrypt(kp, a, seed=1))
    ctb = expand(kp, encrypt(kp, b, seed=2))

    checks = {
        "AND": (dec(kp, gate_and(cta, ctb)), a & b),
        "OR": (dec(kp, gate_or(cta, ctb)), a | b),
        "XOR": (dec(kp, gate_xor(cta, ctb)), a ^ b),
        "NOT(a)": (dec(kp, gate_not(cta)), 1 - a),
        "NAND": (dec(kp, gate_nand(cta, ctb)), 1 - (a & b)),
        "NOR": (dec(kp, gate_nor(cta, ctb)), 1 - (a | b)),
        "XNOR": (dec(kp, gate_xnor(cta, ctb)), 1 - (a ^ b)),
    }

    for name, (got, expected) in checks.items():
        print(f"{name:<8} got={got} expected={expected}")
        assert got == expected


if __name__ == "__main__":
    main()

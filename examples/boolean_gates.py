"""Boolean gates encoded as arithmetic polynomials over F_q."""

from sable import PRESETS, compact_c7, decrypt_c7, encrypt, expand, keygen_c7
from sable import operations as ops


def main() -> None:
    params = PRESETS["c7_standard_toy_clean"]
    kp = keygen_c7(params, seed=42)

    a_val, b_val = 1, 0
    a = expand(kp, encrypt(kp, a_val, seed=43))
    b = expand(kp, encrypt(kp, b_val, seed=44))

    gates = {
        "NOT(a)": ops.gate_not(a),
        "a AND b": ops.gate_and(a, b),
        "a OR b": ops.gate_or(a, b),
        "a XOR b": ops.gate_xor(a, b),
        "a NAND b": ops.gate_nand(a, b),
        "a NOR b": ops.gate_nor(a, b),
        "a XNOR b": ops.gate_xnor(a, b),
    }

    for name, ct in gates.items():
        print(f"{name:10s} -> {decrypt_c7(kp, compact_c7(kp, ct))}")


if __name__ == "__main__":
    main()

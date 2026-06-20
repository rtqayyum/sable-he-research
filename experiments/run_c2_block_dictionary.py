"""Run clean end-to-end checks for the SABLE-HE-C2 block dictionary."""

from __future__ import annotations

from sable.params import PRESETS
from sable.sable import (
    compact_block_c2,
    decrypt_block_c2,
    encrypt,
    eval_add,
    eval_mul,
    expand,
    keygen_block_c2,
)


def enc_exp(kp, x: int, seed: int):
    return expand(kp, encrypt(kp, x, seed=seed))


def main() -> None:
    params = PRESETS["c2_toy_clean"]
    kp = keygen_block_c2(params, seed=2026)
    print(f"preset={params.name} q={params.q} N={params.N} block_size={params.c2_block_size}")
    print(f"dictionary_entries={kp.compaction_dictionary_c2.public_entries}")

    cases = []
    x, y = 4, 6
    ct = eval_mul(enc_exp(kp, x, 1), enc_exp(kp, y, 2))
    got = decrypt_block_c2(kp, compact_block_c2(kp, ct))
    cases.append(("mul", got, (x * y) % params.q))

    x, y, z = 2, 3, 5
    ct = eval_add(eval_mul(enc_exp(kp, x, 3), enc_exp(kp, y, 4)), enc_exp(kp, z, 5))
    got = decrypt_block_c2(kp, compact_block_c2(kp, ct))
    cases.append(("xy_plus_z", got, (x * y + z) % params.q))

    for name, got, expected in cases:
        print(f"case={name} got={got} expected={expected} pass={got == expected}")


if __name__ == "__main__":
    main()

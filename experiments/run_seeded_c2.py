from sable.params import PRESETS
from sable.sable import (
    compact_seeded_block_c2,
    decrypt_seeded_block_c2,
    encrypt,
    eval_add,
    eval_mul,
    expand,
    keygen_seeded_block_c2,
)


def main() -> None:
    params = PRESETS['c2_toy_clean']
    kp = keygen_seeded_block_c2(params, seed=1701)
    print(f"preset={params.name} q={params.q} N={params.N} block={params.c2_block_size}")
    print(f"dictionary_entries={kp.compaction_seeded_dictionary_c2.public_entries}")
    x, y, z = 3, 5, 4
    cx = expand(kp, encrypt(kp, x, seed=1))
    cy = expand(kp, encrypt(kp, y, seed=2))
    cz = expand(kp, encrypt(kp, z, seed=3))
    cxy = eval_mul(cx, cy, oriented=True)
    out_mul = decrypt_seeded_block_c2(kp, compact_seeded_block_c2(kp, cxy))
    out_xy_z = decrypt_seeded_block_c2(kp, compact_seeded_block_c2(kp, eval_add(cxy, cz)))
    print(f"mul: got={out_mul} expected={(x*y) % params.q}")
    print(f"xy_plus_z: got={out_xy_z} expected={(x*y+z) % params.q}")


if __name__ == '__main__':
    main()

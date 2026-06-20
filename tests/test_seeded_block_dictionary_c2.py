from sable.clpn_c3_seeded import build_seeded_dictionary, nonzero_block_count
from sable.params import PRESETS
from sable.regev import extended_secret
from sable.sable import (
    compact_seeded_block_c2,
    decrypt_seeded_block_c2,
    encrypt,
    eval_add,
    eval_mul,
    expand,
    keygen_seeded_block_c2,
)
from sable.sparse import SparseVector


def test_seeded_dictionary_entry_count():
    params = PRESETS['c2_toy_clean']
    kp = keygen_seeded_block_c2(params, seed=300)
    # N=13, block=2, q=7 -> 6 blocks of width 2 and one of width 1.
    expected = 6 * (7**2 - 1) + (7 - 1)
    assert kp.compaction_seeded_dictionary_c2.public_entries == expected


def test_seeded_block_count_for_sparse_row():
    params = PRESETS['c2_toy_clean']
    row = SparseVector(params.N, {0: 3, 1: 2, 4: 6, 11: 1}, params.q)
    assert nonzero_block_count(row, 2) == 3


def test_seeded_block_dictionary_end_to_end_mul_clean():
    kp = keygen_seeded_block_c2(PRESETS['c2_toy_clean'], seed=250)
    x, y = 3, 5
    ct = eval_mul(expand(kp, encrypt(kp, x, seed=1)), expand(kp, encrypt(kp, y, seed=2)), oriented=True)
    assert decrypt_seeded_block_c2(kp, compact_seeded_block_c2(kp, ct)) == (x * y) % kp.params.q


def test_seeded_block_dictionary_end_to_end_xy_plus_z_clean():
    kp = keygen_seeded_block_c2(PRESETS['c2_toy_clean'], seed=251)
    x, y, z = 2, 4, 6
    cx = expand(kp, encrypt(kp, x, seed=10))
    cy = expand(kp, encrypt(kp, y, seed=11))
    cz = expand(kp, encrypt(kp, z, seed=12))
    cxy = eval_mul(cx, cy, oriented=True)
    out = eval_add(cxy, cz)
    assert decrypt_seeded_block_c2(kp, compact_seeded_block_c2(kp, out)) == (x * y + z) % kp.params.q

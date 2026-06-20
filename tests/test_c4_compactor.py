from sable.additive_basis import projective_count
from sable.clpn_c4_basis import active_block_count, compaction_term_count, estimate_c4_key
from sable.params import PRESETS
from sable.sable import (
    compact_basis_c4,
    decrypt_basis_c4,
    direct_decrypt_gsw,
    encrypt,
    eval_add,
    eval_mul,
    expand,
    keygen_basis_c4,
)


def test_c4_projective_key_size_smaller_than_full_c2_dictionary():
    params = PRESETS["c2_toy_clean"]
    est = estimate_c4_key(params, block_size=2, max_terms_per_block=1, mode="projective")
    assert est["c4_entries"] < est["c2_entries"]
    assert projective_count(params.q, 2) == (params.q**2 - 1) // (params.q - 1)


def test_c4_end_to_end_clean_arithmetic_circuit():
    params = PRESETS["c2_toy_clean"]
    kp = keygen_basis_c4(params, seed=4242, block_size=2, max_terms_per_block=1, mode="projective")
    x, y, z = 2, 3, 4
    X = expand(kp, encrypt(kp, x, seed=1))
    Y = expand(kp, encrypt(kp, y, seed=2))
    Z = expand(kp, encrypt(kp, z, seed=3))
    F = eval_add(eval_mul(X, Y), Z)
    direct = direct_decrypt_gsw(kp, F)
    compact = compact_basis_c4(kp, F)
    dec = decrypt_basis_c4(kp, compact)
    assert direct == (x * y + z) % params.q
    assert dec == direct


def test_c4_term_count_is_at_most_one_per_active_block_projective():
    params = PRESETS["c2_toy_clean"]
    kp = keygen_basis_c4(params, seed=11, block_size=2, max_terms_per_block=1, mode="projective")
    ct = expand(kp, encrypt(kp, 5, seed=12))
    row = ct[0].last_row()
    terms = compaction_term_count(row, kp.compaction_basis_c4)
    blocks = active_block_count(row, 2)
    assert terms <= blocks

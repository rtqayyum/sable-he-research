from sable.params import PRESETS
from sable.sable import compact_block_c2, decrypt_block_c2, encrypt, eval_add, eval_mul, expand, keygen_block_c2


def enc_exp(kp, x, seed):
    return expand(kp, encrypt(kp, x, seed=seed))


def test_block_dictionary_c2_end_to_end_mul_clean():
    kp = keygen_block_c2(PRESETS["c2_toy_clean"], seed=250)
    x, y = 4, 6
    ct = eval_mul(enc_exp(kp, x, 251), enc_exp(kp, y, 252))
    assert decrypt_block_c2(kp, compact_block_c2(kp, ct)) == (x * y) % kp.params.q


def test_block_dictionary_c2_end_to_end_xy_plus_z_clean():
    kp = keygen_block_c2(PRESETS["c2_toy_clean"], seed=260)
    x, y, z = 2, 3, 5
    ct = eval_add(eval_mul(enc_exp(kp, x, 261), enc_exp(kp, y, 262)), enc_exp(kp, z, 263))
    assert decrypt_block_c2(kp, compact_block_c2(kp, ct)) == (x * y + z) % kp.params.q

from sable.params import PRESETS
from sable.sable import compact, decrypt, direct_decrypt_gsw, encrypt, eval_add, eval_mul, expand, keygen


def enc_exp(kp, x, seed):
    return expand(kp, encrypt(kp, x, seed=seed))


def test_expand_clean_direct_decrypt():
    kp = keygen(PRESETS["toy_clean"], seed=1)
    ct = enc_exp(kp, 42, seed=2)
    assert direct_decrypt_gsw(kp, ct) == 42


def test_end_to_end_add_clean():
    kp = keygen(PRESETS["toy_clean"], seed=3)
    x, y = 9, 11
    ct = eval_add(enc_exp(kp, x, 4), enc_exp(kp, y, 5))
    assert decrypt(kp, compact(kp, ct)) == (x + y) % kp.params.q


def test_end_to_end_mul_clean():
    kp = keygen(PRESETS["toy_clean"], seed=6)
    x, y = 7, 13
    ct = eval_mul(enc_exp(kp, x, 7), enc_exp(kp, y, 8))
    assert decrypt(kp, compact(kp, ct)) == (x * y) % kp.params.q


def test_end_to_end_xy_plus_z_clean():
    kp = keygen(PRESETS["toy_clean"], seed=9)
    x, y, z = 4, 5, 6
    ct = eval_add(eval_mul(enc_exp(kp, x, 10), enc_exp(kp, y, 11)), enc_exp(kp, z, 12))
    assert decrypt(kp, compact(kp, ct)) == (x * y + z) % kp.params.q

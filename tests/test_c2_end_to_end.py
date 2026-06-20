from sable.params import PRESETS
from sable.sable import compact_c2, decrypt, encrypt, eval_add, eval_mul, expand, keygen_c2


def enc_exp(kp, x, seed):
    return expand(kp, encrypt(kp, x, seed=seed))


def test_c2_end_to_end_add_clean():
    kp = keygen_c2(PRESETS["c2_toy_clean"], seed=30)
    x, y = 3, 5
    ct = eval_add(enc_exp(kp, x, 31), enc_exp(kp, y, 32))
    assert decrypt(kp, compact_c2(kp, ct)) == (x + y) % kp.params.q


def test_c2_end_to_end_mul_clean():
    kp = keygen_c2(PRESETS["c2_toy_clean"], seed=40)
    x, y = 4, 6
    ct = eval_mul(enc_exp(kp, x, 41), enc_exp(kp, y, 42))
    assert decrypt(kp, compact_c2(kp, ct)) == (x * y) % kp.params.q


def test_c2_end_to_end_xy_plus_z_clean():
    kp = keygen_c2(PRESETS["c2_toy_clean"], seed=50)
    x, y, z = 2, 3, 4
    ct = eval_add(eval_mul(enc_exp(kp, x, 51), enc_exp(kp, y, 52)), enc_exp(kp, z, 53))
    assert decrypt(kp, compact_c2(kp, ct)) == (x * y + z) % kp.params.q

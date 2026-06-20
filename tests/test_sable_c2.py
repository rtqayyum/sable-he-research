from sable.params import PRESETS
from sable.sable_c2 import compact, decrypt, direct_decrypt_gsw, encrypt, eval_add, eval_mul, expand, keygen


def enc_exp(kp, x, seed):
    return expand(kp, encrypt(kp, x, seed=seed))


def test_c2_expand_clean_direct_decrypt():
    kp = keygen(PRESETS["toy_clean"], seed=1, deterministic_code=True)
    ct = enc_exp(kp, 42, seed=2)
    assert direct_decrypt_gsw(kp, ct) == 42


def test_c2_end_to_end_add_clean():
    kp = keygen(PRESETS["toy_clean"], seed=3, deterministic_code=True)
    x, y = 9, 11
    ct = eval_add(enc_exp(kp, x, 4), enc_exp(kp, y, 5))
    assert decrypt(kp, compact(kp, ct)) == (x + y) % kp.params.q


def test_c2_end_to_end_mul_clean():
    kp = keygen(PRESETS["toy_clean"], seed=6, deterministic_code=True)
    x, y = 7, 13
    ct = eval_mul(enc_exp(kp, x, 7), enc_exp(kp, y, 8))
    assert decrypt(kp, compact(kp, ct)) == (x * y) % kp.params.q

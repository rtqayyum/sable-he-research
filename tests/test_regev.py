import random

from sable.params import PRESETS
from sable.regev import decrypt_raw, encrypt


def test_regev_clean_decrypts():
    params = PRESETS["toy_clean"]
    rng = random.Random(123)
    t = [rng.randrange(params.q) for _ in range(params.n)]
    for mu in [0, 1, 5, 126]:
        c = encrypt(mu, t, params, rng)
        assert decrypt_raw(c, t, params.q) == mu % params.q

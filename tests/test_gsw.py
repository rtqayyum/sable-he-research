import random

from sable.gsw import encrypt, message_residuals
from sable.params import PRESETS


def test_gsw_clean_residuals_zero():
    params = PRESETS["toy_clean"]
    rng = random.Random(55)
    s = [rng.randrange(params.q) for _ in range(params.n)]
    for alpha in [0, 1, 7, 126]:
        C = encrypt(alpha, s, params, rng)
        assert message_residuals(C, alpha, s) == [0] * params.N

import random

from sable.clpn import decrypt, encrypt, eval_lin
from sable.params import PRESETS
from sable.sparse import SparseVector


def test_clpn_clean_linear_eval():
    params = PRESETS["toy_clean"]
    rng = random.Random(77)
    r = [rng.randrange(params.q) for _ in range(params.n_c)]
    xs = [3, 5, 9]
    key = [encrypt(x, r, params, rng) for x in xs]
    coeffs = SparseVector(3, {0: 2, 1: 4, 2: 1}, params.q)
    z = eval_lin(coeffs, key)
    expected = (2 * 3 + 4 * 5 + 9) % params.q
    assert decrypt(z, r) == expected

import random

from sable import clpn_c2
from sable.params import PRESETS
from sable.sparse import SparseVector


def test_c2_clpn_clean_linear_eval():
    params = PRESETS["toy_clean"]
    rng = random.Random(77)
    r = [rng.randrange(params.q) for _ in range(params.n_c)]
    code = clpn_c2.make_code(params, rng, deterministic=True)
    xs = [3, 5, 9]
    key = [clpn_c2.encrypt(x, r, params, rng, code) for x in xs]
    coeffs = SparseVector(3, {0: 2, 1: 4, 2: 1}, params.q)
    z = clpn_c2.eval_lin(coeffs, key)
    expected = (2 * 3 + 4 * 5 + 9) % params.q
    assert clpn_c2.decrypt(z, r) == expected


def test_c2_clpn_noisy_single_ciphertext_decodes():
    params = PRESETS["toy_noisy"]
    rng = random.Random(12)
    r = [rng.randrange(params.q) for _ in range(params.n_c)]
    code = clpn_c2.make_code(params, rng, deterministic=True)
    ct = clpn_c2.encrypt(41, r, params, rng, code)
    assert clpn_c2.decrypt(ct, r) == 41

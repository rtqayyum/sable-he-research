import random
from sable.clpn_seeded import SeededCLPNCiphertext, decrypt, derive_row, encrypt
from sable.field import dot_dense
from sable.params import PRESETS


def test_derive_row_is_deterministic():
    r1 = derive_row(12345, 2, 8, 127)
    r2 = derive_row(12345, 2, 8, 127)
    r3 = derive_row(12345, 3, 8, 127)
    assert r1 == r2
    assert r1 != r3


def test_seeded_clpn_encrypt_decrypt_clean():
    params = PRESETS['c2_toy_clean']
    rng = random.Random(10)
    secret = [rng.randrange(params.q) for _ in range(params.n_c)]
    ct = encrypt(5, secret, params, rng, seed=777)
    assert decrypt(ct, secret) == 5


def test_seeded_clpn_add_scaled_clean():
    params = PRESETS['c2_toy_clean']
    rng = random.Random(11)
    secret = [rng.randrange(params.q) for _ in range(params.n_c)]
    c1 = encrypt(2, secret, params, rng, seed=100)
    c2 = encrypt(4, secret, params, rng, seed=200)
    out = c1.add_scaled(c2, 3)
    assert decrypt(out, secret) == (2 + 3 * 4) % params.q
    assert len(out.terms) == 2


def test_seeded_aggregate_row_matches_manual_sum():
    params = PRESETS['c2_toy_clean']
    rng = random.Random(12)
    secret = [rng.randrange(params.q) for _ in range(params.n_c)]
    c1 = encrypt(1, secret, params, rng, seed=101)
    c2 = encrypt(2, secret, params, rng, seed=202)
    out = c1.add_scaled(c2, 5)
    row = out.aggregate_row(0)
    lhs = dot_dense(row, secret, params.q)
    rhs = 0
    for coeff, seed in out.terms:
        rhs = (rhs + coeff * dot_dense(derive_row(seed, 0, params.n_c, params.q), secret, params.q)) % params.q
    assert lhs == rhs

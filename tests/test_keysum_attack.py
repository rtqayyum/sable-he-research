"""The key-sum attack recovers a client's key and update when the server knows T."""

import numpy as np

from sable.fast_regev import RegevAggParams, aggregate, choose_replicas, decrypt_sum, encrypt, keygen, plurality
from sable.keysum_attack import _vectors, clean_mask, key_sum_exposure, recover_key
from sable.fast_regev import _dot


def test_key_sum_attack_recovers_key_and_update():
    n, k, q, eta, K, d = 192, 5, 2147483647, 0.003, 6, 40
    R = choose_replicas(n, k, q, eta, K)
    p = RegevAggParams("t", n=n, k=k, q=q, eta=eta, replicas=R)
    rng = np.random.default_rng(3)
    keys = [keygen(p, 50 + c) for c in range(K)]
    msgs = [rng.integers(0, 2**20, size=d) for _ in range(K)]
    ups = [encrypt(p, keys[c], msgs[c], round_seed=11, noise_seed=90 + c) for c in range(K)]
    B = aggregate(ups, q)
    T = sum(keys) % q
    M = decrypt_sum(p, T, B, 11)["value"]
    clean = clean_mask(p, T, B, M, 11)
    t0 = recover_key(p, ups[0], clean, 11)
    assert t0 is not None and np.array_equal(t0, keys[0])
    idx, co = _vectors(p, 11, d)
    val, _, _ = plurality((ups[0] - _dot(idx, co, t0, q)) % q)
    assert np.array_equal(val, msgs[0])


def test_key_sum_exposure_flags_fl_rows():
    p = RegevAggParams("main", n=65536, k=5, q=2147483647, eta=0.003, replicas=13)
    scr = key_sum_exposure(p, d=7850, clients=10)
    assert scr["verdict"] == "broken-if-server-learns-key-sum"
    assert scr["rounds_to_recover_key"] == 1

"""Tests for the sparse-LPN screens/attacks and the vectorized kernels."""

import random
import warnings

import pytest

np = pytest.importorskip("numpy")


def test_screen_rejects_low_sparsity_and_noise_free():
    from sable.sparse_attacks import sparse_layer_screen

    assert sparse_layer_screen(65536, 2, 0.003, 65537, 65537**2).verdict == "broken-or-below-target"
    assert "noise-free" in sparse_layer_screen(16, 1, 0.0, 127, 289).blockers[0]
    ok = sparse_layer_screen(131072, 6, 0.0014, 65537, 131073**2)
    assert ok.verdict == "passes-sparse-screens"


def test_two_sparse_solver_recovers_secret():
    from sable.sparse_attacks import generate_two_sparse_instance, solve_two_sparse_lpn

    inst = generate_two_sparse_instance(2048, 20 * 2048, 65537, 0.003, seed=1)
    out = solve_two_sparse_lpn(inst["I"], inst["J"], inst["ai"], inst["aj"], inst["b"], 2048, 65537)
    assert np.array_equal(out["s"], inst["s"])


def test_known_plaintext_attack_breaks_demo_preset():
    from sable import PRESETS
    from sable.params import InsecureParametersWarning
    from sable.sable import _base_key_material
    from sable.sparse_attacks import recover_s_known_plaintext

    p = PRESETS["fl_demo_clean"]
    with pytest.warns(InsecureParametersWarning):
        t, s, r, _, xkey = _base_key_material(p, random.Random(5))
    s_hat = recover_s_known_plaintext([row.data for row in xkey[p.n].rows], p.n, p.q)
    assert [int(x) for x in s_hat] == list(s)


def test_new_candidates_have_no_hard_blockers():
    from sable.parameter_sets import CANDIDATES, screen_candidate

    for c in CANDIDATES:
        blockers = screen_candidate(c).blockers
        if c.k <= 2:
            assert any("k<=2" in b for b in blockers)
        else:
            assert all(b.startswith("thin") or "compaction key" in b for b in blockers), (c.name, blockers)


def test_fast_regev_key_additive_sum():
    from sable.fast_regev import RegevAggParams, aggregate, decrypt_sum, encrypt, keygen

    p = RegevAggParams("t", n=1024, k=5, q=2147483647, eta=0.003, replicas=9)
    keys = [keygen(p, i) for i in range(6)]
    msgs = [np.arange(500, dtype=np.int64) * (i + 1) for i in range(6)]
    B = aggregate([encrypt(p, k, m, 7, 100 + i) for i, (k, m) in enumerate(zip(keys, msgs))], p.q)
    out = decrypt_sum(p, sum(keys) % p.q, B, 7)
    assert np.array_equal(out["value"], sum(msgs) % p.q)


def test_fast_she_mul_and_add():
    pytest.importorskip("scipy")
    from sable import fast_she as fs

    p = fs.SheParams("t", n=256, k=3, q=fs.Q28, eta=0.0, replicas=3)
    keys = fs.keygen(p, 2)
    A = fs.expand(keys, fs.encrypt(keys, 12, 1))
    B = fs.expand(keys, fs.encrypt(keys, 34, 2))
    assert fs.decrypt(keys, fs.mul(A, B, p.q))[0] == 408
    assert fs.decrypt(keys, fs.add(A, B, p.q))[0] == 46

import random

from sable import arithmetic as A
from sable.c7_relation_resistant import (
    build_basis_key,
    build_screened_basis,
    block_relation_profile,
    coordinate_combination,
    decompose_c7,
    estimate_c7_key,
    first_relation_weight,
    standard_basis,
)
from sable.params import PRESETS
from sable.regev import extended_secret
from sable.sable import (
    compact_c7,
    decrypt_relation_resistant_c7,
    encrypt,
    expand,
    keygen_relation_resistant_c7,
)
from sable.sparse import SparseVector


def test_standard_basis_has_no_kernel_relation_up_to_width():
    q = 7
    basis = standard_basis(4)
    assert first_relation_weight(q, basis, max_weight=4) is None
    profile = block_relation_profile(q, basis, screen_weight=4)
    assert profile["first_relation_weight_up_to_screen"] is None


def test_c7_coordinate_decompose_fallback_exact():
    q = 11
    target = (3, 0, 7, 5)
    comb = decompose_c7(target, standard_basis(4), q, preferred_terms=1)
    assert comb.evaluate(standard_basis(4)) == target
    assert comb.weight == 3
    assert coordinate_combination(target, q).evaluate(standard_basis(4)) == target


def test_screened_random_basis_rejects_low_weight_relations_locally():
    rng = random.Random(123)
    q = 7
    basis = build_screened_basis(q, width=4, entries=6, rng=rng, min_relation_weight=4)
    assert len(basis) >= 4
    # The screen rules out relations of weight below 4.
    assert first_relation_weight(q, basis, max_weight=3) is None


def test_c7_estimator_coordinate_is_default_security_profile():
    params = PRESETS["c4_projective_toy_clean"]
    est = estimate_c7_key(params, block_size=1, mode="coordinate")
    assert est["public_entries"] == params.N
    assert est["security_status"] == "main research default"
    assert est["dense_fallback_terms_bound"] == params.N


def test_c7_key_builds_and_counts_terms():
    params = PRESETS["c4_projective_toy_clean"]
    rng = random.Random(5)
    s = [rng.randrange(params.q) for _ in range(params.n)]
    r = [rng.randrange(params.q) for _ in range(params.n_c)]
    tilde_s = extended_secret(s, params.q)
    key = build_basis_key(tilde_s, r, params, rng, block_size=2, mode="coordinate")
    coeffs = SparseVector(params.N, {0: 3, 2: 4, params.N - 1: 1}, params.q)
    ct = key.blocks[0][0].zero(params.m_c, params.n_c, params.q) if False else None
    from sable.c7_relation_resistant import compaction_term_count, eval_lin, decrypt_c7
    out = eval_lin(coeffs, key)
    assert compaction_term_count(coeffs, key) == 3
    expected = sum(coeffs.data[i] * tilde_s[i] for i in coeffs.data) % params.q
    assert decrypt_c7(out, r) == expected


def _enc(kp, value: int, seed: int):
    return expand(kp, encrypt(kp, value % kp.params.q, seed=seed))


def test_c7_end_to_end_mul_and_add():
    params = PRESETS["c4_projective_toy_clean"]
    kp = keygen_relation_resistant_c7(params, seed=777, block_size=1, mode="coordinate")
    x, y, z = 3, 5, 6
    X = _enc(kp, x, 1)
    Y = _enc(kp, y, 2)
    Z = _enc(kp, z, 3)
    expr = A.add(A.mul(X, Y), Z)
    got = decrypt_relation_resistant_c7(kp, compact_c7(kp, expr))
    assert got == (x * y + z) % params.q


def test_c7_boolean_gates():
    params = PRESETS["c4_projective_toy_clean"]
    kp = keygen_relation_resistant_c7(params, seed=778, block_size=1, mode="coordinate")
    X = _enc(kp, 1, 11)
    Y = _enc(kp, 0, 12)
    got_and = decrypt_relation_resistant_c7(kp, compact_c7(kp, A.gate_and(X, Y)))
    got_or = decrypt_relation_resistant_c7(kp, compact_c7(kp, A.gate_or(X, Y)))
    got_xor = decrypt_relation_resistant_c7(kp, compact_c7(kp, A.gate_xor(X, Y)))
    assert got_and == 0
    assert got_or == 1
    assert got_xor == 1

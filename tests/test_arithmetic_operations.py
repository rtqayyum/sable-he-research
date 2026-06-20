from sable import arithmetic as arith
from sable.params import PRESETS
from sable.sable import compact_basis_c4, decrypt_basis_c4, encrypt, expand, keygen_basis_c4


def _enc(kp, x, seed):
    return expand(kp, encrypt(kp, x % kp.params.q, seed=seed))


def _dec(kp, ct):
    return decrypt_basis_c4(kp, compact_basis_c4(kp, ct))


def test_field_arithmetic_operations_c4_clean():
    kp = keygen_basis_c4(PRESETS["c4_projective_toy_clean"], seed=101)
    q = kp.params.q
    x, y, z = 3, 5, 2
    X, Y, Z = _enc(kp, x, 1), _enc(kp, y, 2), _enc(kp, z, 3)
    cases = {
        "add": (arith.eval_add(X, Y), x + y),
        "sub": (arith.eval_sub(X, Y), x - y),
        "neg": (arith.eval_neg(X), -x),
        "scalar": (arith.eval_scalar(X, 4), 4 * x),
        "add_const": (arith.eval_add_const(X, 6), x + 6),
        "const_minus": (arith.eval_const_minus(6, X), 6 - x),
        "linear_combination": (arith.eval_linear_combination([(2, X), (3, Y), (4, Z)], constant=1), 2*x + 3*y + 4*z + 1),
        "mul": (arith.eval_mul(X, Y), x * y),
        "square": (arith.eval_square(X), x * x),
        "power3": (arith.eval_power(X, 3), x ** 3),
        "poly2": (arith.eval_poly(X, [5, 3, 1]), x*x + 3*x + 5),
    }
    for name, (ct, expected) in cases.items():
        assert _dec(kp, ct) == expected % q, name


def test_boolean_gate_encodings_c4_clean():
    kp = keygen_basis_c4(PRESETS["c4_projective_toy_clean"], seed=202)
    for x in [0, 1]:
        for y in [0, 1]:
            X, Y = _enc(kp, x, 100 + 10*x + y), _enc(kp, y, 200 + 10*x + y)
            assert _dec(kp, arith.bool_not(X)) == 1 - x
            assert _dec(kp, arith.bool_and(X, Y)) == (x & y)
            assert _dec(kp, arith.bool_or(X, Y)) == (x | y)
            assert _dec(kp, arith.bool_xor(X, Y)) == (x ^ y)


def test_fermat_toy_equality_and_inverse_small_q():
    kp = keygen_basis_c4(PRESETS["c4_projective_toy_clean"], seed=303)
    q = kp.params.q
    x = 3
    X = _enc(kp, x, 7)
    assert _dec(kp, arith.eq_const_fermat(X, x)) == 1
    assert _dec(kp, arith.eq_const_fermat(X, (x + 1) % q)) == 0
    assert (_dec(kp, arith.inverse_fermat(X)) * x) % q == 1


def test_active_profile_reports_sparsity():
    kp = keygen_basis_c4(PRESETS["c4_projective_toy_clean"], seed=404)
    X = _enc(kp, 2, 1)
    prof = arith.active_profile(X)
    assert prof["replicas"] == kp.params.replicas
    assert prof["nrows"] == kp.params.N
    assert prof["max_row_support"] >= 1

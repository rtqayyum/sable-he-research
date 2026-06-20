from __future__ import annotations

import pytest

from sable import operations as ops
from sable.params import PRESETS
from sable.sable import (
    compact_basis_c4,
    decrypt_basis_c4,
    direct_decrypt_gsw,
    encrypt,
    expand,
    keygen_basis_c4,
)


def _ct(kp, value, seed):
    return expand(kp, encrypt(kp, value, seed=seed))


def _dec(kp, ct):
    return decrypt_basis_c4(kp, compact_basis_c4(kp, ct)) % kp.params.q


@pytest.fixture(scope="module")
def kp():
    params = PRESETS["c4_projective_toy_clean"]
    return keygen_basis_c4(params, seed=20260619, block_size=2, mode="projective")


def test_native_field_arithmetic_suite(kp):
    q = kp.params.q
    a, b = 5, 3
    A = _ct(kp, a, 11)
    B = _ct(kp, b, 12)

    cases = {
        "zero": (ops.zero_like(A), 0),
        "one": (ops.one_like(A), 1),
        "const": (ops.const_like(A, 4), 4),
        "add": (ops.add(A, B), a + b),
        "sub": (ops.sub(A, B), a - b),
        "neg": (ops.neg(A), -a),
        "scalar_mul": (ops.scalar_mul(A, 4), 4 * a),
        "add_plain": (ops.add_plain(A, 6), a + 6),
        "sub_plain": (ops.sub_plain(A, 6), a - 6),
        "plain_sub": (ops.plain_sub(6, A), 6 - a),
        "mul": (ops.mul(A, B), a * b),
        "mul_oriented": (ops.mul(A, B, oriented=True), a * b),
        "square": (ops.square(A), a * a),
        "pow_0": (ops.pow_plain(A, 0), 1),
        "pow_1": (ops.pow_plain(A, 1), a),
        "pow_3": (ops.pow_plain(A, 3), a**3),
        "inverse_nonzero": (ops.inverse_nonzero(A), pow(a, q - 2, q)),
        "div_nonzero": (ops.div_nonzero(A, B), a * pow(b, q - 2, q)),
    }
    for name, (ct, expected) in cases.items():
        got = _dec(kp, ct)
        assert got == expected % q, f"{name}: got {got}, expected {expected % q}"
        assert direct_decrypt_gsw(kp, ct) % q == expected % q


def test_boolean_polynomial_gates(kp):
    for x in (0, 1):
        for y in (0, 1):
            X = _ct(kp, x, 100 + 10 * x + y)
            Y = _ct(kp, y, 200 + 10 * x + y)
            checks = {
                "AND": (ops.gate_and(X, Y), x & y),
                "OR": (ops.gate_or(X, Y), x | y),
                "XOR": (ops.gate_xor(X, Y), x ^ y),
                "NAND": (ops.gate_nand(X, Y), 1 - (x & y)),
                "NOR": (ops.gate_nor(X, Y), 1 - (x | y)),
                "XNOR": (ops.gate_xnor(X, Y), 1 - (x ^ y)),
            }
            for name, (ct, expected) in checks.items():
                assert _dec(kp, ct) == expected, f"{name}({x},{y})"
            assert _dec(kp, ops.gate_not(X)) == 1 - x


def test_small_polynomial_and_mixed_operations(kp):
    # f(x,y,z)=3x^2 - 2xy + 5z + 4 over F_q.
    q = kp.params.q
    x, y, z = 2, 6, 4
    X = _ct(kp, x, 301)
    Y = _ct(kp, y, 302)
    Z = _ct(kp, z, 303)
    fct = ops.add_plain(
        ops.add(
            ops.sub(ops.scalar_mul(ops.square(X), 3), ops.scalar_mul(ops.mul(X, Y), 2)),
            ops.scalar_mul(Z, 5),
        ),
        4,
    )
    expected = 3 * x * x - 2 * x * y + 5 * z + 4
    assert _dec(kp, fct) == expected % q

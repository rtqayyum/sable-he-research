from __future__ import annotations

import pytest

from sable import arithmetic as A
from sable.params import PRESETS
from sable.sable import compact_basis_c4, decrypt_basis_c4, encrypt, expand, keygen_basis_c4


@pytest.fixture(scope='module')
def kp():
    params = PRESETS['c4_projective_toy_clean']
    return keygen_basis_c4(params, seed=4242, block_size=2, max_terms_per_block=1, mode='projective')


def enc(kp, value, seed):
    return expand(kp, encrypt(kp, value % kp.params.q, seed=seed))


def dec(kp, ct):
    return decrypt_basis_c4(kp, compact_basis_c4(kp, ct))


def test_linear_arithmetic(kp):
    q = kp.params.q
    x, y = 5, 3
    X, Y = enc(kp, x, 1), enc(kp, y, 2)
    assert dec(kp, A.add(X, Y)) == (x + y) % q
    assert dec(kp, A.sub(X, Y)) == (x - y) % q
    assert dec(kp, A.neg(X)) == (-x) % q
    assert dec(kp, A.scalar_mul(X, 4)) == (4 * x) % q
    assert dec(kp, A.add_const(X, 6)) == (x + 6) % q
    assert dec(kp, A.const_sub(6, X)) == (6 - x) % q


def test_nonlinear_arithmetic(kp):
    q = kp.params.q
    x, y = 4, 6
    X, Y = enc(kp, x, 11), enc(kp, y, 12)
    assert dec(kp, A.mul(X, Y)) == (x * y) % q
    assert dec(kp, A.square(X)) == (x * x) % q
    assert dec(kp, A.poly_eval(X, [3, 2, 5])) == (3 + 2*x + 5*x*x) % q


def test_dot_product_and_quadratic_form(kp):
    q = kp.params.q
    xs = [1, 2, 3, 4]
    cts = [enc(kp, x, 100+i) for i, x in enumerate(xs)]
    assert dec(kp, A.dot_public([1, 2, 3, 4], cts, constant=6)) == (1 + 4 + 9 + 16 + 6) % q
    qf = A.add_const(A.add(A.mul(cts[0], cts[1]), A.mul(cts[2], cts[3])), 5)
    assert dec(kp, qf) == (xs[0]*xs[1] + xs[2]*xs[3] + 5) % q


@pytest.mark.parametrize('x,y', [(0,0), (0,1), (1,0), (1,1)])
def test_boolean_gates(kp, x, y):
    X, Y = enc(kp, x, 200+10*x+y), enc(kp, y, 300+10*x+y)
    assert dec(kp, A.gate_and(X, Y)) == (x & y)
    assert dec(kp, A.gate_or(X, Y)) == (x | y)
    assert dec(kp, A.gate_xor(X, Y)) == (x ^ y)
    assert dec(kp, A.gate_nand(X, Y)) == 1 - (x & y)
    assert dec(kp, A.gate_nor(X, Y)) == 1 - (x | y)
    assert dec(kp, A.gate_xnor(X, Y)) == 1 - (x ^ y)
    assert dec(kp, A.gate_implies(X, Y)) == int((not x) or bool(y))
    assert dec(kp, A.gate_not(X)) == 1 - x

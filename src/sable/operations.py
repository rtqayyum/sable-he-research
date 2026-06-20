"""High-level arithmetic operations for expanded SABLE ciphertexts.

The native message space is the prime field F_q.  Operations in this module
act on expanded GSW-style ciphertext replicas, i.e. list[SparseMatrix].  They
are public evaluation operations and do not use the secret key.

Supported native operations:
  - zero, one, constants
  - addition, subtraction, negation
  - scalar/plain multiplication
  - plaintext addition/subtraction
  - multiplication, square, powers
  - nonzero inversion/division by Fermat exponentiation (for small q only)
  - Boolean gates encoded as arithmetic polynomials over F_q

Important limitation: ordering/comparison and true division are not native.  A
nonzero inverse can be evaluated as x^(q-2), which is multiplicatively deep and
is undefined at x=0.  This is suitable for tiny-field validation only.
"""

from __future__ import annotations

from . import gsw
from .sparse import SparseMatrix, SparseVector

ExpandedCiphertext = list[SparseMatrix]


def _check_replicas(ct: ExpandedCiphertext) -> None:
    if not ct:
        raise ValueError("ciphertext must contain at least one replica")
    q = ct[0].q
    nrows, ncols = ct[0].nrows, ct[0].ncols
    for C in ct:
        if C.q != q or C.nrows != nrows or C.ncols != ncols:
            raise ValueError("incompatible replicas")


def _identity_matrix_like(C: SparseMatrix) -> SparseMatrix:
    rows = [SparseVector(C.ncols, {i: 1}, C.q) for i in range(C.nrows)]
    return SparseMatrix(C.nrows, C.ncols, rows, C.q)


def zero_like(ct: ExpandedCiphertext) -> ExpandedCiphertext:
    _check_replicas(ct)
    return [SparseMatrix.zero(C.nrows, C.ncols, C.q) for C in ct]


def const_like(ct: ExpandedCiphertext, value: int) -> ExpandedCiphertext:
    """Return an expanded ciphertext encrypting a public constant.

    In the GSW representation, beta*I encrypts beta exactly because
    (beta I) * tilde{s} = beta * tilde{s}.
    """
    _check_replicas(ct)
    return [_identity_matrix_like(C).scale(value % C.q) for C in ct]


def one_like(ct: ExpandedCiphertext) -> ExpandedCiphertext:
    return const_like(ct, 1)


def add(left: ExpandedCiphertext, right: ExpandedCiphertext) -> ExpandedCiphertext:
    if len(left) != len(right):
        raise ValueError("replica mismatch")
    return [gsw.eval_add(a, b) for a, b in zip(left, right)]


def sub(left: ExpandedCiphertext, right: ExpandedCiphertext) -> ExpandedCiphertext:
    if len(left) != len(right):
        raise ValueError("replica mismatch")
    return [a.add_scaled(b, -1) for a, b in zip(left, right)]


def neg(ct: ExpandedCiphertext) -> ExpandedCiphertext:
    return scalar_mul(ct, -1)


def scalar_mul(ct: ExpandedCiphertext, scalar: int) -> ExpandedCiphertext:
    _check_replicas(ct)
    return [C.scale(scalar % C.q) for C in ct]


def add_plain(ct: ExpandedCiphertext, value: int) -> ExpandedCiphertext:
    return add(ct, const_like(ct, value))


def sub_plain(ct: ExpandedCiphertext, value: int) -> ExpandedCiphertext:
    return sub(ct, const_like(ct, value))


def plain_sub(value: int, ct: ExpandedCiphertext) -> ExpandedCiphertext:
    return sub(const_like(ct, value), ct)


def mul(left: ExpandedCiphertext, right: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    if len(left) != len(right):
        raise ValueError("replica mismatch")
    if oriented:
        return [gsw.eval_mul_oriented(a, b) for a, b in zip(left, right)]
    return [gsw.eval_mul(a, b) for a, b in zip(left, right)]


def square(ct: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    return mul(ct, ct, oriented=oriented)


def pow_plain(ct: ExpandedCiphertext, exponent: int, *, oriented: bool = False) -> ExpandedCiphertext:
    """Exponentiate an encrypted field element by a public nonnegative integer."""
    if exponent < 0:
        raise ValueError("negative exponents require inversion; use inverse_nonzero")
    if exponent == 0:
        return one_like(ct)
    result = one_like(ct)
    base = ct
    e = int(exponent)
    while e:
        if e & 1:
            result = mul(result, base, oriented=oriented)
        e >>= 1
        if e:
            base = mul(base, base, oriented=oriented)
    return result


def inverse_nonzero(ct: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    """Evaluate x^{-1}=x^{q-2} for nonzero x in F_q.

    This is expensive and only intended for small q in validation tests.  It
    does not define a meaningful inverse for x=0.
    """
    _check_replicas(ct)
    q = ct[0].q
    return pow_plain(ct, q - 2, oriented=oriented)


def div_nonzero(num: ExpandedCiphertext, den: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    return mul(num, inverse_nonzero(den, oriented=oriented), oriented=oriented)


# Boolean gates over bits embedded as 0/1 in F_q.

def gate_and(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    return mul(x, y, oriented=oriented)


def gate_not(x: ExpandedCiphertext) -> ExpandedCiphertext:
    return plain_sub(1, x)


def gate_or(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    # x OR y = x + y - xy over {0,1} embedded in F_q.
    return sub(add(x, y), mul(x, y, oriented=oriented))


def gate_xor(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    # x XOR y = x + y - 2xy over {0,1} embedded in any odd prime field.
    return sub(add(x, y), scalar_mul(mul(x, y, oriented=oriented), 2))


def gate_nand(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    return gate_not(gate_and(x, y, oriented=oriented))


def gate_nor(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    return gate_not(gate_or(x, y, oriented=oriented))


def gate_xnor(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    return gate_not(gate_xor(x, y, oriented=oriented))


def gate_implies(x: ExpandedCiphertext, y: ExpandedCiphertext, *, oriented: bool = False) -> ExpandedCiphertext:
    """Boolean implication x -> y over bits embedded in F_q.

    For x,y in {0,1}, implication is (NOT x) OR y = 1 - x + xy.
    """
    return gate_or(gate_not(x), y, oriented=oriented)

# Higher-level low-degree arithmetic helpers.

def affine_combination(terms: list[tuple[int, ExpandedCiphertext]], constant: int = 0) -> ExpandedCiphertext:
    """Evaluate constant + sum_i alpha_i * ct_i with public coefficients."""
    if not terms:
        raise ValueError("at least one term is required to define the ciphertext shape")
    acc = const_like(terms[0][1], constant)
    for alpha, ct in terms:
        acc = add(acc, scalar_mul(ct, alpha))
    return acc


def dot(coeffs: list[int], ciphertexts: list[ExpandedCiphertext], constant: int = 0) -> ExpandedCiphertext:
    """Evaluate a public-coefficient encrypted dot product."""
    if len(coeffs) != len(ciphertexts):
        raise ValueError("coefficient/ciphertext length mismatch")
    return affine_combination(list(zip(coeffs, ciphertexts)), constant=constant)


def dot_public(coeffs: list[int], ciphertexts: list[ExpandedCiphertext], constant: int = 0) -> ExpandedCiphertext:
    """Alias for dot."""
    return dot(coeffs, ciphertexts, constant=constant)


def poly_eval(ct: ExpandedCiphertext, coeffs_low_to_high: list[int], *, oriented: bool = False) -> ExpandedCiphertext:
    """Evaluate p(x)=sum_i coeffs[i] x^i using Horner's rule."""
    if not coeffs_low_to_high:
        raise ValueError("polynomial must have at least one coefficient")
    acc = const_like(ct, coeffs_low_to_high[-1])
    for coeff in reversed(coeffs_low_to_high[:-1]):
        acc = add_plain(mul(acc, ct, oriented=oriented), coeff)
    return acc


def product(ciphertexts: list[ExpandedCiphertext], *, oriented: bool = False) -> ExpandedCiphertext:
    """Evaluate a left-associated product of encrypted field elements."""
    if not ciphertexts:
        raise ValueError("at least one ciphertext is required")
    acc = ciphertexts[0]
    for ct in ciphertexts[1:]:
        acc = mul(acc, ct, oriented=oriented)
    return acc


def balanced_product(ciphertexts: list[ExpandedCiphertext], *, oriented: bool = False) -> ExpandedCiphertext:
    """Evaluate a balanced multiplication tree over encrypted field elements."""
    if not ciphertexts:
        raise ValueError("at least one ciphertext is required")
    level = list(ciphertexts)
    while len(level) > 1:
        next_level: list[ExpandedCiphertext] = []
        it = iter(level)
        for first in it:
            second = next(it, None)
            if second is None:
                next_level.append(first)
            else:
                next_level.append(mul(first, second, oriented=oriented))
        level = next_level
    return level[0]


def quadratic_form(
    ciphertexts: list[ExpandedCiphertext],
    terms: list[tuple[int, int, int]],
    constant: int = 0,
    *,
    oriented: bool = False,
) -> ExpandedCiphertext:
    """Evaluate constant + sum_(coef,i,j) coef * x_i * x_j.

    `terms` contains triples `(coef, i, j)`. This representation is compact and
    avoids requiring any third-party matrix dependency.
    """
    if not ciphertexts:
        raise ValueError("at least one ciphertext is required")
    acc = const_like(ciphertexts[0], constant)
    for coef, i, j in terms:
        prod = mul(ciphertexts[i], ciphertexts[j], oriented=oriented)
        acc = add(acc, scalar_mul(prod, coef))
    return acc

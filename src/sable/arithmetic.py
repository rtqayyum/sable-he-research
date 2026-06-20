"""Public arithmetic operations for expanded SABLE-HE ciphertexts.

The encrypted value carried by a GSW-style ciphertext C is the scalar mu in

    C * tilde{s} = mu * tilde{s} + error.

Therefore exact public constants are represented by alpha * I_N.  From this
observation the validation prototype exposes the full low-degree arithmetic
interface used by the paper: addition, subtraction, negation, public scalar
multiplication, public constants, multiplication, powers, polynomial
evaluation, affine combinations, and Boolean gates encoded as arithmetic over
F_q.  Division by an encrypted value, comparisons, sign, min/max, and table
lookup are not native operations here; they must be represented as bounded
arithmetic/Boolean circuits before evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .sparse import SparseMatrix, SparseVector

Ciphertext = list[SparseMatrix]


def _require_nonempty(ct: Ciphertext) -> None:
    if not ct:
        raise ValueError('ciphertext replica list cannot be empty')


def _require_same_shape(left: Ciphertext, right: Ciphertext) -> None:
    _require_nonempty(left)
    _require_nonempty(right)
    if len(left) != len(right):
        raise ValueError('replica mismatch')
    for a, b in zip(left, right):
        if a.nrows != b.nrows or a.ncols != b.ncols or a.q != b.q:
            raise ValueError('ciphertext shape mismatch')


def identity_matrix(size: int, q: int, scale: int = 1) -> SparseMatrix:
    """Return scale * I_size over F_q as a sparse matrix."""
    s = scale % q
    if s == 0:
        return SparseMatrix.zero(size, size, q)
    rows = [SparseVector(size, {i: s}, q) for i in range(size)]
    return SparseMatrix(size, size, rows, q)


def constant_like(reference: Ciphertext, value: int) -> Ciphertext:
    """Return an exact public-constant ciphertext with the same replica shape."""
    _require_nonempty(reference)
    q = reference[0].q
    return [identity_matrix(C.nrows, q, value) for C in reference]


def add(left: Ciphertext, right: Ciphertext) -> Ciphertext:
    _require_same_shape(left, right)
    return [a.add(b) for a, b in zip(left, right)]


def sub(left: Ciphertext, right: Ciphertext) -> Ciphertext:
    _require_same_shape(left, right)
    q = left[0].q
    return [a.add_scaled(b, q - 1) for a, b in zip(left, right)]


def neg(ct: Ciphertext) -> Ciphertext:
    _require_nonempty(ct)
    q = ct[0].q
    return [C.scale(q - 1) for C in ct]


def scalar_mul(ct: Ciphertext, scalar: int) -> Ciphertext:
    _require_nonempty(ct)
    return [C.scale(scalar) for C in ct]


def add_const(ct: Ciphertext, constant: int) -> Ciphertext:
    return add(ct, constant_like(ct, constant))


def sub_const(ct: Ciphertext, constant: int) -> Ciphertext:
    return sub(ct, constant_like(ct, constant))


def const_sub(constant: int, ct: Ciphertext) -> Ciphertext:
    return sub(constant_like(ct, constant), ct)


def mul(left: Ciphertext, right: Ciphertext, *, oriented: bool = False) -> Ciphertext:
    _require_same_shape(left, right)
    if oriented:
        return [a.matmul(b) if a.max_row_support() <= b.max_row_support() else b.matmul(a) for a, b in zip(left, right)]
    return [a.matmul(b) for a, b in zip(left, right)]


def square(ct: Ciphertext) -> Ciphertext:
    return mul(ct, ct)


def pow_public(ct: Ciphertext, exponent: int) -> Ciphertext:
    """Evaluate ct^exponent by square-and-multiply with public exponent."""
    if exponent < 0:
        raise ValueError('negative exponents require encrypted inversion, which is not native')
    _require_nonempty(ct)
    result = constant_like(ct, 1)
    base = ct
    e = exponent
    while e:
        if e & 1:
            result = mul(result, base)
        e >>= 1
        if e:
            base = square(base)
    return result


def affine_combination(terms: Sequence[tuple[int, Ciphertext]], constant: int = 0) -> Ciphertext:
    """Evaluate constant + sum_i alpha_i * ct_i."""
    if not terms:
        raise ValueError('at least one term is required to define the shape')
    acc = constant_like(terms[0][1], constant)
    for alpha, ct in terms:
        acc = add(acc, scalar_mul(ct, alpha))
    return acc


def dot_public(coeffs: Sequence[int], ciphertexts: Sequence[Ciphertext], constant: int = 0) -> Ciphertext:
    if len(coeffs) != len(ciphertexts):
        raise ValueError('coefficient/ciphertext length mismatch')
    return affine_combination(list(zip(coeffs, ciphertexts)), constant=constant)


def poly_eval(ct: Ciphertext, coeffs_low_to_high: Sequence[int]) -> Ciphertext:
    """Evaluate p(x)=sum_i coeffs[i] x^i using Horner's rule."""
    if not coeffs_low_to_high:
        raise ValueError('polynomial must have at least one coefficient')
    _require_nonempty(ct)
    acc = constant_like(ct, coeffs_low_to_high[-1])
    for coeff in reversed(coeffs_low_to_high[:-1]):
        acc = add_const(mul(acc, ct), coeff)
    return acc


def product(ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
    if not ciphertexts:
        raise ValueError('at least one ciphertext is required')
    acc = ciphertexts[0]
    for ct in ciphertexts[1:]:
        acc = mul(acc, ct)
    return acc


def balanced_product(ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
    if not ciphertexts:
        raise ValueError('at least one ciphertext is required')
    level = list(ciphertexts)
    while len(level) > 1:
        next_level: list[Ciphertext] = []
        it = iter(level)
        for first in it:
            second = next(it, None)
            if second is None:
                next_level.append(first)
            else:
                next_level.append(mul(first, second))
        level = next_level
    return level[0]


# Boolean gates over inputs encoded as 0/1 in F_q.
def gate_not(x: Ciphertext) -> Ciphertext:
    return const_sub(1, x)


def gate_and(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    return mul(x, y)


def gate_or(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    return sub(add(x, y), mul(x, y))


def gate_xor(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    return sub(add(x, y), scalar_mul(mul(x, y), 2))


def gate_nand(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    return gate_not(gate_and(x, y))


def gate_nor(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    return gate_not(gate_or(x, y))


def gate_xnor(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    return gate_not(gate_xor(x, y))


def gate_implies(x: Ciphertext, y: Ciphertext) -> Ciphertext:
    # x -> y equals 1 - x + xy for Boolean x,y.
    return add(gate_not(x), mul(x, y))


@dataclass(frozen=True)
class OperationProfile:
    name: str
    inputs: int
    additions: int
    subtractions: int
    scalar_muls: int
    public_constants: int
    ciphertext_multiplications: int
    multiplicative_depth: int
    tfhe_boolean_gate_proxy: int
    bfv_bgv_ct_adds: int
    bfv_bgv_ct_muls: int
    notes: str

    @property
    def linear_ops(self) -> int:
        return self.additions + self.subtractions + self.scalar_muls + self.public_constants


OPERATION_PROFILES: dict[str, OperationProfile] = {
    'add': OperationProfile('add', 2, 1, 0, 0, 0, 0, 0, 0, 1, 0, 'encrypted x+y over F_q'),
    'sub': OperationProfile('sub', 2, 0, 1, 0, 0, 0, 0, 0, 1, 0, 'encrypted x-y over F_q'),
    'neg': OperationProfile('neg', 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 'public scalar -1 times encrypted x'),
    'scalar_mul': OperationProfile('scalar_mul', 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 'public scalar times encrypted x'),
    'add_const': OperationProfile('add_const', 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 'x+c using public exact cI_N'),
    'mul': OperationProfile('mul', 2, 0, 0, 0, 0, 1, 1, 1, 0, 1, 'encrypted multiplication x*y'),
    'square': OperationProfile('square', 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 'encrypted square x^2'),
    'affine': OperationProfile('affine', 2, 2, 0, 2, 1, 0, 0, 0, 2, 0, '3x+2y+5'),
    'dot4': OperationProfile('dot4', 4, 4, 0, 4, 1, 0, 0, 0, 4, 0, 'public-coefficient dot product'),
    'poly2': OperationProfile('poly2', 1, 2, 0, 1, 2, 2, 2, 2, 2, 2, '3+2x+5x^2 via Horner'),
    'product4': OperationProfile('product4', 4, 0, 0, 0, 0, 3, 2, 3, 0, 3, 'balanced product x1*x2*x3*x4'),
    'quadratic_form': OperationProfile('quadratic_form', 4, 2, 0, 0, 1, 2, 1, 2, 2, 2, 'x1*x2+x3*x4+5'),
    'and': OperationProfile('and', 2, 0, 0, 0, 0, 1, 1, 1, 0, 1, 'Boolean AND as xy'),
    'or': OperationProfile('or', 2, 1, 1, 0, 0, 1, 1, 1, 2, 1, 'Boolean OR as x+y-xy'),
    'xor': OperationProfile('xor', 2, 1, 1, 1, 0, 1, 1, 1, 2, 1, 'Boolean XOR as x+y-2xy'),
    'not': OperationProfile('not', 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 'Boolean NOT as 1-x'),
    'nand': OperationProfile('nand', 2, 0, 1, 0, 1, 1, 1, 1, 1, 1, 'Boolean NAND as 1-xy'),
    'nor': OperationProfile('nor', 2, 1, 1, 0, 1, 1, 1, 1, 3, 1, 'Boolean NOR as 1-(x+y-xy)'),
    'xnor': OperationProfile('xnor', 2, 1, 1, 1, 1, 1, 1, 1, 3, 1, 'Boolean XNOR as 1-(x+y-2xy)'),
    'implies': OperationProfile('implies', 2, 1, 1, 0, 1, 1, 1, 1, 2, 1, 'Boolean implication as 1-x+xy'),
}

# Backward-compatible names used by earlier validation tests and package exports.
zero_like = lambda ct: [SparseMatrix.zero(C.nrows, C.ncols, C.q) for C in ct]
const_like = constant_like
one_like = lambda ct: constant_like(ct, 1)
eval_add = add
eval_sub = sub
eval_neg = neg
eval_scalar = scalar_mul
eval_add_const = add_const
eval_sub_const = sub_const
eval_const_minus = const_sub
eval_mul = mul
eval_square = square
eval_power = pow_public
eval_linear_combination = affine_combination
bool_not = gate_not
bool_and = gate_and
bool_or = gate_or
bool_xor = gate_xor
bool_nand = gate_nand
bool_nor = gate_nor
bool_xnor = gate_xnor


def inverse_fermat(ct: Ciphertext) -> Ciphertext:
    """Evaluate x^(q-2), valid as inverse only for nonzero plaintexts."""
    _require_nonempty(ct)
    return pow_public(ct, ct[0].q - 2)


def eq_const_fermat(ct: Ciphertext, constant: int) -> Ciphertext:
    """Evaluate equality-to-constant as 1 - (x-c)^(q-1) over F_q."""
    _require_nonempty(ct)
    return const_sub(1, pow_public(sub_const(ct, constant), ct[0].q - 1))


def active_profile(ct: Ciphertext) -> dict[str, int]:
    _require_nonempty(ct)
    return {
        'replicas': len(ct),
        'nrows': ct[0].nrows,
        'ncols': ct[0].ncols,
        'q': ct[0].q,
        'max_row_support': max(C.max_row_support() for C in ct),
        'total_nnz': sum(C.total_nnz() for C in ct),
    }
eval_poly = poly_eval

# Compatibility aliases used by the v0.7 public API and benchmark scripts.
const_like = constant_like
eval_add = add
eval_sub = sub
eval_neg = neg
eval_scalar = scalar_mul
eval_add_const = add_const
eval_sub_const = sub_const
eval_const_minus = const_sub
eval_mul = mul
eval_square = square
eval_power = pow_public
eval_linear_combination = affine_combination
eval_poly = poly_eval
bool_not = gate_not
bool_and = gate_and
bool_or = gate_or
bool_xor = gate_xor


def zero_like(reference: Ciphertext) -> Ciphertext:
    _require_nonempty(reference)
    return [SparseMatrix.zero(C.nrows, C.ncols, C.q) for C in reference]


def one_like(reference: Ciphertext) -> Ciphertext:
    return constant_like(reference, 1)


def eq_const_fermat(ct: Ciphertext, value: int, *, oriented: bool = False) -> Ciphertext:
    _require_nonempty(ct)
    q = ct[0].q
    return const_sub(1, pow_public(sub_const(ct, value % q), q - 1))


def inverse_fermat(ct: Ciphertext, *, oriented: bool = False) -> Ciphertext:
    _require_nonempty(ct)
    q = ct[0].q
    return pow_public(ct, q - 2)


def active_profile(ct: Ciphertext) -> dict[str, int | float]:
    _require_nonempty(ct)
    total = sum(C.total_nnz() for C in ct)
    return {
        'replicas': len(ct),
        'nrows': ct[0].nrows,
        'ncols': ct[0].ncols,
        'max_row_support': max(C.max_row_support() for C in ct),
        'total_nnz': total,
        'avg_total_nnz_per_replica': total / len(ct),
    }

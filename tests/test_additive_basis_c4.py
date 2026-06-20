import random

from sable.additive_basis import decompose_sparse, projective_count, projective_representatives, random_basis


def test_projective_representatives_cover_all_nonzero_vectors_weight_one():
    q, width = 5, 3
    basis = projective_representatives(q, width)
    assert len(basis) == projective_count(q, width)
    for a in range(q):
        for b in range(q):
            for c in range(q):
                target = (a, b, c)
                comb = decompose_sparse(target, basis, q, 1)
                assert comb.evaluate(basis) == target
                assert comb.weight <= (0 if target == (0, 0, 0) else 1)


def test_random_basis_has_standard_fallback_for_small_weight_targets():
    q, width = 7, 4
    rng = random.Random(10)
    basis = random_basis(q, width, 10, rng, include_standard=True)
    target = (3, 0, 5, 0)
    comb = decompose_sparse(target, basis, q, 2)
    assert comb.evaluate(basis) == target
    assert comb.weight <= 2

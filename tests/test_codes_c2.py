import random

from sable.codes import WeightedRepetitionCode, qary_plurality_failure_bound


def test_weighted_repetition_decodes_clean_residuals():
    q = 127
    code = WeightedRepetitionCode.deterministic(17, q)
    x = 42
    assert code.decode(code.encode(x)) == x


def test_weighted_repetition_decodes_sparse_errors():
    q = 127
    code = WeightedRepetitionCode.deterministic(31, q)
    residuals = code.encode(9)
    residuals[0] = (residuals[0] + 5) % q
    residuals[5] = (residuals[5] + 7) % q
    assert code.decode(residuals) == 9


def test_qary_plurality_bound_improves_over_binary_threshold_region():
    # With large q, p=0.7 can still be decodable by plurality because wrong
    # votes are dispersed among q-1 symbols.  The bound should be nontrivial.
    assert qary_plurality_failure_bound(m=512, q=65537, error_rate=0.7) < 1e-6

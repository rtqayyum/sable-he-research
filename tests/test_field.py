from sable.field import is_prime, qary_piling_up, repetition_failure_bound


def test_is_prime():
    assert is_prime(127)
    assert is_prime(65537)
    assert not is_prime(128)


def test_qary_piling_up_zero_terms():
    assert qary_piling_up(127, 0.01, 0) == 0.0


def test_repetition_bound():
    assert repetition_failure_bound(81, 0.0) == 0.0
    assert repetition_failure_bound(81, 0.6) == 1.0

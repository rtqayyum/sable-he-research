
from sable.attacks import clean_subset_bits, prange_isd_bits, security_report
from sable.params import PRESETS


def test_clean_subset_bits_zero_noise_is_zero():
    assert clean_subset_bits(16, 100, 0.0) == 0.0


def test_clean_subset_bits_increases_with_dimension():
    small = clean_subset_bits(16, 100, 0.01)
    large = clean_subset_bits(32, 100, 0.01)
    assert large > small > 0


def test_prange_zero_noise_is_zero():
    assert prange_isd_bits(100, 20, 0.0) == 0.0


def test_security_report_has_blockers_for_toy_noisy():
    report = security_report(PRESETS['toy_noisy'], target_bits=128)
    assert not report['passes_screen']
    assert report['blockers']

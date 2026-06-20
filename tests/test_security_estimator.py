from sable.params import PRESETS
from sable.security_estimator import estimate_security, log2_binom, report_to_jsonable


def test_log2_binom_basic():
    assert log2_binom(10, 0) == 0
    assert abs(log2_binom(10, 1) - 3.321928094887362) < 1e-12
    assert abs(log2_binom(10, 9) - log2_binom(10, 1)) < 1e-12


def test_security_report_jsonable():
    report = estimate_security(PRESETS['toy_noisy'])
    data = report_to_jsonable(report)
    assert data['params']['name'] == 'toy_noisy'
    assert 'layers' in data
    assert len(data['layers']) == 2
    assert data['public_sample_counts']['total_public_sparse_lpn_rows'] > 0

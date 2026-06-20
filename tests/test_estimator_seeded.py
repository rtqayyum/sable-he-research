from sable.estimator_seeded import estimate_seeded_c2
from sable.params import PRESETS
from sable.qary_lpn_estimator import estimate_qary_lpn_surface, qary_bkw_block_scan


def test_seeded_estimator_reports_storage_reduction():
    est = estimate_seeded_c2(PRESETS['c2_toy_noisy'], depth=1)
    assert est['c3_dictionary_entries'] > 0
    assert est['storage_estimates']['field_entry_storage_reduction_factor'] > 1.0
    assert est['attack_surfaces']['seeded_dictionary_compaction']['samples'] == est['c3_public_clpn_samples']


def test_qary_surface_estimator_has_bkw_block_scan():
    p = PRESETS['c2_toy_noisy']
    report = estimate_qary_lpn_surface(name='unit', n=p.n_c, q=p.q, eta=p.eta_c, samples=1000)
    assert 'qary_bkw_block_scan' in report
    assert report['sample_to_dimension_ratio'] > 0


def test_qary_bkw_scan_returns_candidate():
    scan = qary_bkw_block_scan(32, 7, 0.01, 100000)
    assert scan.block_size >= 1
    assert scan.levels >= 1

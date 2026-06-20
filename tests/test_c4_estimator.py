from sable.c4_estimator import compare, screen_projective, screen_random
from sable.params import PRESETS


def test_c4_estimator_reports_entry_reduction_against_c2():
    params = PRESETS["c2_design_smallq"]
    cmp = compare(params, max_terms_per_block=1)
    assert cmp.c4_entries < cmp.c2_entries
    assert 0 < cmp.c4_vs_c2_ratio < 1
    assert cmp.terms_c4_bound == cmp.terms_c2


def test_c4_basis_screens_run():
    params = PRESETS["c2_toy_clean"]
    proj = screen_projective(params)
    rnd = screen_random(params, entries=12, terms=2, samples=20)
    assert proj["sample_coverage_rate"] == 1.0
    assert 0.0 <= rnd["sample_coverage_rate"] <= 1.0

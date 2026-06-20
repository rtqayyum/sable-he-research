from sable.estimator_c2 import c2_compaction_terms_worst, c2_dictionary_entries, summarize_params_c2
from sable.params import PRESETS


def test_c2_dictionary_entries_formula():
    # N=13, ell=2, q=7 -> six full blocks and one singleton block.
    assert c2_dictionary_entries(7, 13, 2) == 6 * (7**2 - 1) + (7 - 1)


def test_c2_compaction_terms_worst():
    assert c2_compaction_terms_worst(13, 2, 13) == 7
    assert c2_compaction_terms_worst(13, 2, 3) == 3


def test_c2_estimator_reports_reduced_terms():
    est = summarize_params_c2(PRESETS["c2_toy_noisy"], depth=1)
    assert est["c2_compaction_terms_worst"] <= est["v1_coordinate_compaction_terms"]
    assert est["c2_dictionary_entries"] > PRESETS["c2_toy_noisy"].N

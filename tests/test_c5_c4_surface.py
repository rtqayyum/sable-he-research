from sable.c5_c4_surface import c4_min_relation_weight_screen, estimate_c4_surface, format_surface_report
from sable.params import PRESETS


def test_c5_surface_counts_c4_projective():
    report = estimate_c4_surface(PRESETS["c4_projective_toy_clean"])
    assert report.c4_projective_entries < report.c2_full_dictionary_entries
    assert report.clpn_compaction_rows == report.c4_projective_entries * PRESETS["c4_projective_toy_clean"].m_c
    assert report.minimum_linear_relation_weight_screen == 3
    assert "C4 projective entries" in format_surface_report(report)


def test_projective_min_relation_screen():
    assert c4_min_relation_weight_screen(7, 1) == 0
    assert c4_min_relation_weight_screen(7, 2) == 3
    assert c4_min_relation_weight_screen(7, 3) == 3

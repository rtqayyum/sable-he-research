from __future__ import annotations

from sable.c5_attack_estimator import estimate_c4_surface, projective_entries, relation_weight_projective
from sable.operation_support import rows_as_dicts
from sable.params import PRESETS


def test_projective_entries_formula():
    assert projective_entries(7, 1) == 1
    assert projective_entries(7, 2) == 8
    assert projective_entries(3, 3) == 13


def test_c5_surface_estimator_c4_toy():
    report = estimate_c4_surface(PRESETS["c4_projective_toy_noisy"], block_size=2)
    assert report.c4_public_entries > 0
    assert report.c4_public_entries < report.c2_public_entries_if_full_dictionary
    assert report.c4_vs_c2_entry_ratio < 1
    assert report.c4_compaction_terms_bound == report.num_blocks
    assert all(block.min_relation_weight_heuristic == block.width + 1 for block in report.block_surfaces)


def test_relation_weight_heuristic():
    assert relation_weight_projective(1) == 2
    assert relation_weight_projective(2) == 3
    assert relation_weight_projective(4) == 5


def test_operation_support_matrix_mentions_division_limit():
    rows = rows_as_dicts()
    div = next(row for row in rows if row["operation"] == "division")
    assert "not native" in div["sable_c4"]

from __future__ import annotations

from sable.c5_surface import estimate_c5_surface
from sable.params import PRESETS


def test_c5_surface_projective_reduces_c2():
    params = PRESETS['c4_projective_toy_noisy']
    report = estimate_c5_surface(params, relation_trials=25, seed=5)
    assert report.c4_projective_entries < report.c2_entries
    assert report.c4_public_clpn_rows == report.c4_projective_entries * params.m_c
    assert report.low_weight_2_relation_found is False
    assert report.low_weight_3_relation_found is True

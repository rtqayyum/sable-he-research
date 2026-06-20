from __future__ import annotations

import math

from sable.c6_relation_estimator import (
    estimate_c6_relations,
    gaussian_binomial_2,
    projective_point_count,
    projective_relation_space_dimension,
    surface_counts,
    weight3_projective_relations,
)
from sable.params import PRESETS


def test_projective_counts_basic() -> None:
    assert projective_point_count(7, 1) == 1
    assert projective_point_count(7, 2) == 8
    assert projective_point_count(3, 3) == 13
    assert projective_relation_space_dimension(7, 2) == 6


def test_gaussian_binomial_and_weight3_relations_pg1() -> None:
    # PG(1,q) has one projective line with q+1 points.
    q = 7
    assert gaussian_binomial_2(q, 2) == 1
    assert weight3_projective_relations(q, 2) == math.comb(q + 1, 3)


def test_no_weight3_for_width_one() -> None:
    assert gaussian_binomial_2(7, 1) == 0
    assert weight3_projective_relations(7, 1) == 0


def test_c6_surface_detects_c4_relations() -> None:
    p = PRESETS["c4_projective_toy_noisy"]
    counts = surface_counts(p)
    assert counts.c4_projective_entries > 0
    assert counts.raw_weight3_relations > 0
    assert counts.weight3_relation_noise > p.eta_c


def test_c6_report_rejects_width_two_projective_screen() -> None:
    p = PRESETS["c4_projective_toy_noisy"]
    report = estimate_c6_relations(p)
    assert report.verdict == "reject-for-current-security-claim"
    assert any("weight-3" in blocker for blocker in report.blockers)
    assert report.lpn_screens

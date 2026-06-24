from pathlib import Path

from sable import attack_estimators_phase8 as ae
from sable import lpn_estimators


def test_estimator_info_lists_attack_families():
    info = ae.attack_estimator_info()
    assert info["schema"] == "sable-phase8-strengthened-attack-estimator-v1"
    assert any("BKW" in family for family in info["models"])


def test_attack_report_has_surfaces_and_estimates():
    report = ae.estimate_candidate("sable_cat1_depth1_review", target_bits=128)
    assert report.schema == "sable-phase8-strengthened-attack-estimator-v1"
    assert len(report.surface_reports) >= 4
    assert report.overall_verdict in {"requires-specialist-review-or-redesign", "passes-internal-screens-only"}


def test_lpn_estimators_cli_backend_runs():
    report = lpn_estimators.estimate_candidate("sable_cat1_depth1_review", target_bits=128)
    assert report.target_bits == 128
    assert report.surfaces


def test_write_attack_package(tmp_path: Path):
    manifest = ae.write_attack_package(tmp_path / "pkg", names=["sable_cat1_depth1_review"])
    assert manifest["schema"] == "sable-phase8-strengthened-attack-estimator-v1"
    assert (tmp_path / "pkg" / "summary.csv").exists()
    assert any(name.endswith("_attack_report.json") for name in manifest["files"])

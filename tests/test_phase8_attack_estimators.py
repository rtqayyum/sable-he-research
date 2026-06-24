from pathlib import Path

from sable import attack_estimators_phase8 as ae


def test_phase8_info():
    info = ae.attack_estimator_info()
    assert info["schema"].startswith("sable-phase8")
    assert "BKW" in " ".join(info["models"])


def test_surface_estimate_for_candidate():
    report = ae.estimate_candidate("sable_cat1_depth1_review")
    assert report.candidate == "sable_cat1_depth1_review"
    assert report.surface_reports
    assert report.global_min_classical_bits >= 0
    assert report.overall_verdict in {"passes-internal-screens-only", "requires-specialist-review-or-redesign"}


def test_attack_package_generation(tmp_path: Path):
    manifest = ae.write_attack_package(tmp_path / "pkg", names=["sable_cat1_depth1_review"])
    assert manifest["schema"].startswith("sable-phase8")
    assert (tmp_path / "pkg" / "manifest.json").exists()
    assert (tmp_path / "pkg" / "summary.csv").exists()
    assert any(name.endswith("_attack_report.json") for name in manifest["files"])

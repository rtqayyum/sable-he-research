from pathlib import Path

from sable import parameter_sets


def test_phase7_info_contains_candidates():
    info = parameter_sets.parameter_framework_info()
    assert info["version"]
    assert info["candidates"]
    assert "certified" in " ".join(info["not_claimed"])


def test_candidate_reports_have_required_fields():
    names = parameter_sets.candidate_names()
    assert "sable_cat1_depth1_review" in names
    report = parameter_sets.evaluate_candidate("sable_cat1_depth1_review")
    assert report["candidate"]["target_bits"] == 128
    assert "computed" in report or "correctness_and_size" in report
    assert "minimum_screen_bits" in report or "minimum_finite_screen_bits" in str(report)
    assert "review" in report.get("review_positioning", report.get("disclaimer", "review")).lower()


def test_parameter_package_generation(tmp_path: Path):
    manifest = parameter_sets.write_parameter_package(tmp_path / "pkg")
    assert manifest["candidate_count"] >= 3
    assert (tmp_path / "pkg" / "candidate_parameters.json").exists() or (tmp_path / "pkg" / "candidate_reports.json").exists()
    assert (tmp_path / "pkg" / "candidate_parameters.csv").exists() or (tmp_path / "pkg" / "candidate_summary.csv").exists()
    assert (tmp_path / "pkg" / "README.md").exists()

from pathlib import Path

from sable.standardization import (
    parameter_template,
    readiness_report,
    review_checklist,
    security_assumptions_spec,
    standardization_info,
    write_review_package,
)


def test_standardization_info_scope():
    info = standardization_info()
    assert info["schema"] == "sable-standardization-review-v1"
    assert "post-quantum code/LPN" in info["correct_claim"]
    assert any("certified" in x for x in info["not_claimed"])


def test_readiness_report_has_red_items():
    report = readiness_report()
    assert report["overall_status"] == "pre-standardization-review"
    statuses = {item["status"] for item in report["items"]}
    assert "red" in statuses
    assert "amber" in statuses


def test_security_assumptions_spec_mentions_lpn():
    spec = security_assumptions_spec()
    names = " ".join(item["name"] for item in spec["assumptions"])
    assert "LPN" in names
    assert len(spec["assumptions"]) >= 3


def test_parameter_template_not_certified():
    t = parameter_template("c7_standard_toy_noisy")
    assert t.security_target_bits == 128
    assert "not a certified" in t.intended_use


def test_review_checklist_categories():
    checklist = review_checklist()
    categories = {row["category"] for row in checklist}
    assert {"correctness", "security", "parameters", "implementation", "standardization"}.issubset(categories)


def test_write_review_package(tmp_path: Path):
    manifest = write_review_package(tmp_path / "review", presets=["c7_standard_toy_noisy"], depth=1)
    assert manifest["status"] == "written"
    assert (tmp_path / "review" / "standardization_manifest.json").exists()
    assert (tmp_path / "review" / "review_checklist.csv").exists()
    assert (tmp_path / "review" / "CRYPTANALYSIS_DISCLOSURE_TEMPLATE.md").exists()

from pathlib import Path

from sable import advanced_attacks


def test_phase8_info():
    info = advanced_attacks.phase8_info()
    assert info["schema"] == "sable-phase8-attack-estimator-v1"
    assert "BKW" in " ".join(info["scope"])


def test_estimate_candidate_has_surfaces():
    report = advanced_attacks.estimate_candidate("sable_cat1_depth1_review")
    payload = report.to_jsonable()
    assert payload["candidate"] == "sable_cat1_depth1_review"
    assert len(payload["surfaces"]) >= 4
    assert payload["minimum_bits"] >= 0


def test_bkw_scan_returns_best():
    scan = advanced_attacks.bkw_scan(q=127, dimension=64, samples=4096, eta=0.01)
    assert scan["scan_count"] > 0
    assert "total_bits" in scan["best"]


def test_write_attack_package(tmp_path: Path):
    manifest = advanced_attacks.write_attack_package(tmp_path / "pkg", names=["sable_cat1_depth1_review"])
    assert manifest["candidate_count"] == 1
    assert (tmp_path / "pkg" / "candidate_attack_reports.json").exists()
    assert (tmp_path / "pkg" / "attack_costs.csv").exists()

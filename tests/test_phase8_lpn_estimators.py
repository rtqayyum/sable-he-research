from pathlib import Path

from sable import lpn_estimators as est


def test_qary_piling_up_monotone():
    a = est.qary_piling_up(31, 0.001, 1)
    b = est.qary_piling_up(31, 0.001, 5)
    assert 0 < a < b < 1


def test_custom_surface_estimate():
    s = est.AttackSurface("unit", "q-ary LPN", n=64, q=31, eta=0.01, samples=4096)
    r = est.estimate_surface(s, est.EstimatorConfig(target_bits=64))
    families = {x.family for x in r.estimates}
    assert "clean-subset" in families
    assert "prange-isd" in families
    assert "qary-block-bkw" in families
    assert r.minimum_classical_bits >= 0


def test_candidate_report_jsonable():
    r = est.estimate_candidate("sable_cat1_depth1_review", target_bits=128)
    payload = est.to_jsonable(r)
    assert payload["candidate"] == "sable_cat1_depth1_review"
    assert payload["surfaces"]
    assert payload["verdict"] in {"passes-internal-screens-only", "requires-external-review"}


def test_estimator_package(tmp_path: Path):
    manifest = est.write_estimator_package(tmp_path, candidates=["sable_cat1_depth1_review"], target_bits=128)
    assert (tmp_path / "manifest.json").exists()
    assert (tmp_path / "surface_summary.csv").exists()
    assert manifest["candidates"] == ["sable_cat1_depth1_review"]

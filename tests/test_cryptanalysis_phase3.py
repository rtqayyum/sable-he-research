import json
from pathlib import Path

from sable.params import PRESETS
from sable.cryptanalysis import build_review_bundle, collect_manifest, collect_public_surfaces, write_review_bundle


def test_collect_public_surfaces():
    surfaces = collect_public_surfaces(PRESETS["toy_noisy"])
    names = {s.name for s in surfaces}
    assert "expansion_key_sparse_lpn_rows" in names
    assert "compaction_key_qary_lpn_rows" in names
    assert all(s.public_samples > 0 for s in surfaces)


def test_build_review_bundle_jsonable():
    bundle = build_review_bundle(PRESETS["toy_noisy"], target_bits=64)
    data = bundle.to_jsonable()
    assert data["package"] == "sable-he-research"
    assert data["preset"] == "toy_noisy"
    assert data["surfaces"]
    assert data["non_claims"]


def test_write_review_bundle(tmp_path: Path):
    paths = write_review_bundle(tmp_path, preset="toy_noisy", target_bits=64)
    assert Path(paths["json"]).exists()
    assert Path(paths["markdown"]).exists()
    assert Path(paths["surfaces"]).exists()
    data = json.loads(Path(paths["json"]).read_text())
    assert data["preset"] == "toy_noisy"


def test_manifest_collects_files(tmp_path: Path):
    (tmp_path / "a.py").write_text("print('x')\n")
    manifest = collect_manifest(tmp_path)
    assert manifest and manifest[0].sha256

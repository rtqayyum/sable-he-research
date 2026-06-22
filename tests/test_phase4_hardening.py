from __future__ import annotations

from pathlib import Path

from sable import hardening, phase4


def test_generate_and_verify_kat_bundle(tmp_path: Path):
    manifest = hardening.generate_kat_bundle(tmp_path)
    assert manifest.status == "pass"
    result = hardening.verify_kat_bundle(tmp_path)
    assert result["status"] == "pass"
    assert (tmp_path / "sable_v050_arithmetic_kat.json").exists()


def test_phase4_wrapper_kat_bundle(tmp_path: Path):
    manifest = phase4.write_kat_bundle(str(tmp_path))
    assert manifest["status"] == "pass"
    assert phase4.verify_kat_bundle(str(tmp_path))["status"] == "pass"


def test_scan_public_repo_detects_forbidden_files(tmp_path: Path):
    (tmp_path / "README.md").write_text("x")
    (tmp_path / "LICENSE").write_text("x")
    (tmp_path / "SECURITY.md").write_text("x")
    (tmp_path / "CITATION.cff").write_text("cff-version: 1.2.0\nversion: 0.5.0\n")
    (tmp_path / "pyproject.toml").write_text("version = \"0.5.0\"")
    (tmp_path / "VERSION").write_text("0.5.0\n")
    (tmp_path / "src" / "sable").mkdir(parents=True)
    for name in ["__init__.py", "hardening.py", "cryptanalysis.py", "pqc.py"]:
        (tmp_path / "src" / "sable" / name).write_text("")
    (tmp_path / "docs" / "phase4").mkdir(parents=True)
    (tmp_path / "docs" / "phase4" / "PHASE4_HARDENING_GUIDE.md").write_text("x")
    (tmp_path / "docs" / "phase4" / "KNOWN_ANSWER_TESTS.md").write_text("x")
    (tmp_path / "vectors").mkdir()
    (tmp_path / "vectors" / "sable_v050_arithmetic_kat.json").write_text("{}")
    (tmp_path / "paper").mkdir()
    (tmp_path / "paper" / "draft.pdf").write_text("private")
    result = hardening.scan_public_repo(tmp_path)
    assert result.status == "fail"
    assert "paper/" in result.forbidden_paths or "paper/draft.pdf" in result.forbidden_paths


def test_version_consistency_on_repository_root():
    result = hardening.version_consistency(".")
    assert result["schema"].endswith("version-consistency")
    assert result["status"] == "pass"


def test_phase4_info_shape():
    info = phase4.phase4_info()
    assert info["version"]
    assert "deterministic known-answer vector generation and verification" in info["capabilities"]


def test_phase4_release_artifact_check_shape(tmp_path: Path):
    phase4.write_kat_bundle(str(tmp_path / "vectors"))
    result = phase4.release_artifact_check(str(tmp_path))
    assert result["schema"] == "sable-phase4-release-artifact-check-v1"
    assert "hygiene" in result

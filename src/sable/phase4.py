"""Compatibility wrapper for Phase 4 hardening commands.

The public API is in :mod:`sable.hardening`; this module provides the command
names used by the CLI and older docs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from importlib import resources
from typing import Any

from . import hardening
from .version import __release_name__, __version__


@dataclass(frozen=True)
class HygieneFinding:
    severity: str
    path: str
    reason: str


@dataclass(frozen=True)
class PublicRepoHygieneReport:
    status: str
    scanned_files: int
    findings: list[HygieneFinding]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "schema": "sable-phase4-public-hygiene-wrapper-v1",
            "version": __version__,
            "status": self.status,
            "scanned_files": self.scanned_files,
            "findings": [asdict(f) for f in self.findings],
        }


def phase4_info() -> dict[str, Any]:
    return {
        "schema": "sable-phase4-info-v1",
        "version": __version__,
        "release_name": __release_name__,
        "status": "hardening-reference-preparation; not certified production cryptography",
        "capabilities": [
            "deterministic known-answer vector generation and verification",
            "public repository hygiene scan",
            "release-gate checks for metadata, vectors, and public artifacts",
            "artifact manifest generation",
            "future native-core preparation notes",
        ],
        "non_goals": [
            "FIPS 140-3 validation",
            "certified SABLE-HE parameter sets",
            "side-channel certification",
            "claiming the demo PQC provider is production secure",
        ],
    }


def generate_kats(output: str = "vectors") -> dict[str, Any]:
    return write_kat_bundle(output)


def write_kat_bundle(output: str = "vectors") -> dict[str, Any]:
    return asdict(hardening.generate_kat_bundle(output))


def _resolve_default_vectors_path(path: str) -> str:
    if path in {"vectors", "vectors/phase4"} and not Path(path).exists():
        try:
            return str(resources.files("sable").joinpath("phase4_vectors"))
        except Exception:
            return path
    return path


def verify_kat_bundle(path: str = "vectors/phase4") -> dict[str, Any]:
    return hardening.verify_kat_bundle(_resolve_default_vectors_path(path))


def public_repo_hygiene(path: str = ".") -> PublicRepoHygieneReport:
    report = hardening.scan_public_repo(path)
    findings: list[HygieneFinding] = []
    for rel in report.forbidden_paths:
        findings.append(HygieneFinding("error", rel, "private, generated, build, or paper artifact should not be public"))
    for rel in report.missing_required_files:
        findings.append(HygieneFinding("error", rel, "required public release file is missing"))
    return PublicRepoHygieneReport(status=report.status, scanned_files=report.scanned_files, findings=findings)


def release_artifact_check(path: str = ".") -> dict[str, Any]:
    root = Path(path)
    hygiene = public_repo_hygiene(path).to_jsonable()
    versions = hardening.version_consistency(path)
    required_workflows = [
        ".github/workflows/ci.yml",
        ".github/workflows/release-check.yml",
        ".github/workflows/publish-pypi.yml",
    ]
    missing_workflows = [wf for wf in required_workflows if not (root / wf).exists()]
    vectors_dir = root / "vectors" / "phase4"
    kat = hardening.verify_kat_bundle(vectors_dir) if vectors_dir.exists() else {"status": "fail", "reason": "vectors directory missing"}
    status = "pass" if hygiene["status"] == "pass" and versions["status"] == "pass" and kat["status"] == "pass" and not missing_workflows else "fail"
    return {
        "schema": "sable-phase4-release-artifact-check-v1",
        "version": __version__,
        "status": status,
        "hygiene": hygiene,
        "version_consistency": versions,
        "known_answer_vectors": kat,
        "missing_workflows": missing_workflows,
        "note": "Release-engineering check only; not cryptographic certification.",
    }

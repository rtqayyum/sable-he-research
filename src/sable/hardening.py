"""Phase 4 hardening and release-engineering helpers.

The helpers in this module are dependency-free public release tools. They
support public-repository hygiene checks, deterministic known-answer test (KAT)
vectors, release-gate summaries, and artifact manifests for the SABLE-HE
research package. They do not certify cryptographic security.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from . import cryptanalysis
from .fl import EncryptedFLAggregator
from .params import PRESETS
from .pqc import (
    DemoPQCProvider,
    PQCSuite,
    fingerprint,
    make_signed_federated_update_envelope,
    open_federated_update_envelope,
)
from .version import __release_name__, __version__

SCHEMA = "sable-phase4-hardening-v1"

FORBIDDEN_DIR_NAMES = {
    "paper", "papers", "latex", "audits", "experiments", "benchmarks",
    "_renders", "docs/generated", "dist", "build",
}

FORBIDDEN_SUFFIXES = {
    ".pdf", ".aux", ".bbl", ".blg", ".fls", ".fdb_latexmk",
    ".synctex.gz",
}

REQUIRED_PUBLIC_FILES = {
    "README.md", "LICENSE", "SECURITY.md", "CITATION.cff", "pyproject.toml",
    "VERSION", "src/sable/__init__.py", "src/sable/hardening.py",
    "src/sable/cryptanalysis.py", "src/sable/pqc.py",
    "docs/phase4/PHASE4_HARDENING_GUIDE.md",
    "docs/phase4/KNOWN_ANSWER_TESTS.md",
    "vectors/phase4/sable_v050_arithmetic_kat.json",
}


@dataclass(frozen=True)
class HygieneReport:
    schema: str
    version: str
    status: str
    root: str
    forbidden_paths: list[str]
    missing_required_files: list[str]
    scanned_files: int


@dataclass(frozen=True)
class KatManifest:
    schema: str
    version: str
    release_name: str
    status: str
    output_dir: str
    files: list[dict[str, str]]


@dataclass(frozen=True)
class ReleaseGateReport:
    schema: str
    version: str
    status: str
    gates: list[dict[str, Any]]


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return str(obj)


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_json_default).encode("utf-8")


def write_json(path: str | Path, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, default=_json_default) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_forbidden_relative(rel: Path) -> bool:
    rel_text = rel.as_posix()
    parts = rel_text.split("/")
    if any(part in FORBIDDEN_DIR_NAMES for part in parts):
        return True
    if any(rel_text == name or rel_text.startswith(name + "/") for name in FORBIDDEN_DIR_NAMES):
        return True
    return any(rel_text.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def scan_public_repo(root: str | Path = ".") -> HygieneReport:
    root_path = Path(root).resolve()
    forbidden: list[str] = []
    scanned = 0
    for path in root_path.rglob("*"):
        rel = path.relative_to(root_path)
        if ".git" in rel.parts:
            continue
        if path.is_dir():
            if _is_forbidden_relative(rel):
                forbidden.append(rel.as_posix() + "/")
            continue
        scanned += 1
        if _is_forbidden_relative(rel):
            forbidden.append(rel.as_posix())
    missing = sorted(str(p) for p in REQUIRED_PUBLIC_FILES if not (root_path / p).exists())
    status = "pass" if not forbidden and not missing else "fail"
    return HygieneReport(
        schema=f"{SCHEMA}.hygiene",
        version=__version__,
        status=status,
        root=str(root_path),
        forbidden_paths=sorted(forbidden),
        missing_required_files=missing,
        scanned_files=scanned,
    )


def version_consistency(root: str | Path = ".") -> dict[str, Any]:
    root_path = Path(root)
    readings: dict[str, str | None] = {}
    version_file = root_path / "VERSION"
    readings["VERSION"] = version_file.read_text(encoding="utf-8").strip() if version_file.exists() else None
    pyproject = root_path / "pyproject.toml"
    if pyproject.exists():
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), flags=re.MULTILINE)
        readings["pyproject.toml"] = m.group(1) if m else None
    else:
        readings["pyproject.toml"] = None
    version_py = root_path / "src/sable/version.py"
    if version_py.exists():
        m = re.search(r'__version__\s*=\s*"([^"]+)"', version_py.read_text(encoding="utf-8"))
        readings["src/sable/version.py"] = m.group(1) if m else None
    else:
        readings["src/sable/version.py"] = None
    unique = {v for v in readings.values() if v is not None}
    return {
        "schema": f"{SCHEMA}.version-consistency",
        "expected": __version__,
        "readings": readings,
        "status": "pass" if unique == {__version__} else "fail",
    }


def arithmetic_kat(seed: int = 4040, preset: str = "c7_standard_toy_clean") -> dict[str, Any]:
    vec = cryptanalysis.known_answer_vector(preset, key_seed=seed)
    payload = asdict(vec)
    payload["phase4_schema"] = f"{SCHEMA}.arithmetic-kat"
    payload["kat_digest"] = sha256_bytes(canonical_json_bytes({k: v for k, v in payload.items() if k != "kat_digest"}))
    return payload


def fl_kat(seed: int = 5151, preset: str = "fl_demo_clean") -> dict[str, Any]:
    params = PRESETS[preset]
    agg = EncryptedFLAggregator.from_params(params, key_seed=seed, scale=1000, seed=seed + 1000)
    client_models = [[0.12, -0.34, 1.20], [0.10, -0.30, 1.25], [0.20, -0.40, 1.10]]
    sample_counts = [80, 20, 100]
    encrypted = [agg.encrypt_model(model, seed=seed + 10000 * i) for i, model in enumerate(client_models)]
    result = agg.decrypt_model(agg.fedavg(encrypted, sample_counts))
    expected = [0.158, -0.366, 1.155]
    payload = {
        "schema": f"{SCHEMA}.fl-kat",
        "package": "sable-he-research",
        "version": __version__,
        "preset": preset,
        "key_seed": seed,
        "scale": 1000,
        "client_models": client_models,
        "sample_counts": sample_counts,
        "result": result,
        "expected": expected,
        "status": "pass" if all(abs(a - b) < 1e-12 for a, b in zip(result, expected)) else "fail",
    }
    payload["kat_digest"] = sha256_bytes(canonical_json_bytes({k: v for k, v in payload.items() if k != "kat_digest"}))
    return payload


def pqc_envelope_kat(seed: bytes = b"sable-phase4-pqc-kat-seed") -> dict[str, Any]:
    provider = DemoPQCProvider(allow_insecure_demo=True, seed=seed)
    recipient = provider.kem_keypair("ML-KEM-768")
    signer = provider.signature_keypair("ML-DSA-65")
    update = {"weights": [0.158, -0.366, 1.155], "client_count": 3}
    suite = PQCSuite(kem="ML-KEM-768", signature="ML-DSA-65")
    env = make_signed_federated_update_envelope(
        update,
        sample_count=200,
        round_id="phase4-kat-round",
        client_id="phase4-client",
        recipient_kem_public_key=recipient.public_key,
        sender_signature_secret_key=signer.secret_key,
        sender_signature_public_key=signer.public_key,
        provider=provider,
        suite=suite,
    )
    opened, metadata = open_federated_update_envelope(
        env,
        recipient_kem_secret_key=recipient.secret_key,
        provider=provider,
        trusted_sender_signature_public_key=signer.public_key,
    )
    payload = {
        "schema": f"{SCHEMA}.pqc-envelope-kat",
        "package": "sable-he-research",
        "version": __version__,
        "provider": provider.provider_name,
        "provider_production_capable": provider.production_capable,
        "suite": asdict(suite),
        "recipient_fingerprint": fingerprint(recipient.public_key),
        "signer_fingerprint": fingerprint(signer.public_key),
        "envelope_schema": env.schema,
        "payload_kind": env.payload_kind,
        "metadata": metadata,
        "opened_payload": opened,
        "expected_payload": update,
        "roundtrip_ok": opened == update,
        "status": "pass" if opened == update else "fail",
    }
    payload["kat_digest"] = sha256_bytes(canonical_json_bytes({k: v for k, v in payload.items() if k != "kat_digest"}))
    return payload


def cryptanalysis_kat(preset: str = "toy_noisy") -> dict[str, Any]:
    params = PRESETS[preset]
    report = cryptanalysis.attack_surface_report(params, depth=1, target_bits=128)
    payload = {
        "schema": f"{SCHEMA}.cryptanalysis-kat",
        "package": "sable-he-research",
        "version": __version__,
        "preset": preset,
        "report_schema": report["schema"],
        "target_bits": report["target_bits"],
        "verdict": report["verdict"],
        "surface_summary": report["surface_summary"],
        "minimum_finite_screen_bits": report.get("security_screen", {}).get("minimum_finite_screen_bits"),
        "status": "pass" if report.get("surface_summary", {}).get("preset") == preset else "fail",
    }
    payload["kat_digest"] = sha256_bytes(canonical_json_bytes({k: v for k, v in payload.items() if k != "kat_digest"}))
    return payload


def generate_kat_bundle(output_dir: str | Path = "vectors") -> KatManifest:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    vectors = {
        "sable_v050_arithmetic_kat.json": arithmetic_kat(),
        "sable_v050_fl_kat.json": fl_kat(),
        "sable_v050_pqc_envelope_kat.json": pqc_envelope_kat(),
        "sable_v050_cryptanalysis_kat.json": cryptanalysis_kat(),
    }
    files: list[dict[str, str]] = []
    for name, payload in vectors.items():
        path = out / name
        write_json(path, payload)
        files.append({"path": path.name, "sha256": sha256_file(path), "schema": str(payload.get("schema", ""))})
    manifest = KatManifest(
        schema=f"{SCHEMA}.kat-manifest",
        version=__version__,
        release_name=__release_name__,
        status="pass" if all(v.get("status") == "pass" for v in vectors.values()) else "fail",
        output_dir=str(out),
        files=files,
    )
    write_json(out / "sable_v050_kat_manifest.json", asdict(manifest))
    return manifest


def verify_kat_bundle(vectors_dir: str | Path = "vectors/phase4") -> dict[str, Any]:
    vectors_path = Path(vectors_dir)
    comparisons: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sable-phase4-kat-") as tmp:
        scratch = Path(tmp)
        expected_manifest = generate_kat_bundle(scratch)
        for item in expected_manifest.files:
            name = item["path"]
            actual = vectors_path / name
            regen = scratch / name
            actual_exists = actual.exists()
            digest_actual = sha256_file(actual) if actual_exists else None
            digest_regen = sha256_file(regen)
            comparisons.append({
                "path": name,
                "actual_exists": actual_exists,
                "actual_sha256": digest_actual,
                "regenerated_sha256": digest_regen,
                "match": actual_exists and digest_actual == digest_regen,
            })
    status = "pass" if all(c["match"] for c in comparisons) else "fail"
    return {"schema": f"{SCHEMA}.kat-verification", "version": __version__, "status": status, "comparisons": comparisons}


def artifact_manifest(root: str | Path = ".", *, include: Iterable[str] = ("src", "tests", "docs", "examples", "vectors", "tools")) -> dict[str, Any]:
    root_path = Path(root).resolve()
    rows: list[dict[str, Any]] = []
    for top in include:
        base = root_path / top
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                rel = path.relative_to(root_path).as_posix()
                rows.append({"path": rel, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    return {"schema": f"{SCHEMA}.artifact-manifest", "version": __version__, "file_count": len(rows), "files": rows}


def write_artifact_manifest(root: str | Path = ".", output: str | Path = "docs/phase4/ARTIFACT_MANIFEST.json") -> dict[str, Any]:
    manifest = artifact_manifest(root)
    write_json(output, manifest)
    return manifest


def release_gate(root: str | Path = ".", *, vectors_dir: str | Path = "vectors/phase4") -> ReleaseGateReport:
    hygiene = scan_public_repo(root)
    versions = version_consistency(root)
    kat_report = verify_kat_bundle(vectors_dir) if Path(vectors_dir).exists() else {"status": "fail", "reason": "vectors directory missing"}
    gates = [
        {"name": "version_consistency", "status": versions["status"], "detail": versions},
        {"name": "public_repo_hygiene", "status": hygiene.status, "detail": asdict(hygiene)},
        {"name": "known_answer_vectors", "status": kat_report["status"], "detail": kat_report},
        {"name": "production_crypto_certification", "status": "not-certified", "detail": "Phase 4 improves engineering readiness but does not certify SABLE-HE parameters."},
    ]
    status = "pass" if all(g["status"] in {"pass", "not-certified"} for g in gates) else "fail"
    return ReleaseGateReport(schema=f"{SCHEMA}.release-gate", version=__version__, status=status, gates=gates)

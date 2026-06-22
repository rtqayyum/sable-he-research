"""Independent cryptanalysis support utilities for SABLE-HE.

This module prepares public-review bundles for external cryptanalysts. It does
not certify security and does not turn the Python package into production
cryptography.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .c7_relation_screen import estimate_c7_relations
from .estimator import estimate
from .params import PRESETS, SableParams
from .qary_lpn_estimator import estimate_qary_lpn_surface
from .version import __release_name__, __version__

ATTACK_FAMILIES = [
    "sparse q-ary LPN distinguishing and search",
    "dense q-ary LPN/code decoding",
    "BKW-family sample-combination attacks",
    "information-set decoding and Prange/Stern-style attacks",
    "low-noise clean-subset and linear-solve attacks",
    "large-sample public-key and evaluation-key attacks",
    "relation-surface attacks on compaction keys",
]

REVIEW_SCOPE = [
    "public expansion-key sparse-LPN rows",
    "public compaction-key q-ary LPN/code rows",
    "input ciphertext accumulation in federated-learning deployments",
    "row-difference samples derived from CLPN compaction ciphertexts",
    "relation-resistant coordinate-compaction assumptions",
    "implementation choices such as seeding, serialization, and tensor adapters",
]


def _json_float_or_none(value: float | None) -> float | str | None:
    if value is None:
        return None
    if math.isinf(value):
        return "inf" if value > 0 else "-inf"
    if math.isnan(value):
        return "nan"
    return value


def _parse_screen_bits(value: Any) -> float | None:
    if value is None:
        return None
    if value == "inf":
        return float("inf")
    if value == "-inf":
        return float("-inf")
    try:
        return float(value)
    except Exception:
        return None


@dataclass(frozen=True)
class ReviewSurface:
    name: str
    assumption_family: str
    secret_dimension: int
    q: int
    noise_rate: float
    public_samples: int
    row_weight: int | None
    sample_to_dimension_ratio: float
    expected_errors: float
    review_priority: str
    notes: str

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


CryptanalysisSurface = ReviewSurface


@dataclass(frozen=True)
class CryptanalysisReport:
    package: str
    version: str
    release_name: str
    preset: str
    target_bits: float
    status: str
    surfaces: list[ReviewSurface]
    correctness_estimate: dict[str, Any]
    relation_report: dict[str, Any]
    qary_lpn_screens: list[dict[str, Any]]
    minimum_screen_bits: float | None
    blockers: list[str]
    mandatory_review_questions: list[str]
    acceptance_criteria: list[str]
    non_claims: list[str]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "release_name": self.release_name,
            "preset": self.preset,
            "target_bits": self.target_bits,
            "status": self.status,
            "surfaces": [s.to_jsonable() for s in self.surfaces],
            "correctness_estimate": self.correctness_estimate,
            "relation_report": self.relation_report,
            "qary_lpn_screens": self.qary_lpn_screens,
            "minimum_screen_bits": _json_float_or_none(self.minimum_screen_bits),
            "blockers": self.blockers,
            "mandatory_review_questions": self.mandatory_review_questions,
            "acceptance_criteria": self.acceptance_criteria,
            "non_claims": self.non_claims,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# SABLE-HE independent cryptanalysis bundle: `{self.preset}`",
            "",
            f"Package version: `{self.version}`",
            f"Release: `{self.release_name}`",
            f"Target screen: `{self.target_bits:g}` bits",
            f"Status: **{self.status}**",
            "",
            "## Public surfaces",
            "",
            "| Surface | Assumption | n | q | eta | samples | row weight | sample/n | priority |",
            "|---|---|---:|---:|---:|---:|---:|---:|---|",
        ]
        for s in self.surfaces:
            rw = "-" if s.row_weight is None else str(s.row_weight)
            lines.append(
                f"| {s.name} | {s.assumption_family} | {s.secret_dimension} | {s.q} | {s.noise_rate:.6g} | "
                f"{s.public_samples} | {rw} | {s.sample_to_dimension_ratio:.3g} | {s.review_priority} |"
            )
        if self.blockers:
            lines.extend(["", "## Internal screen blockers", ""])
            lines.extend(f"- {b}" for b in self.blockers)
        lines.extend(["", "## Mandatory review questions", ""])
        lines.extend(f"- {q}" for q in self.mandatory_review_questions)
        lines.extend(["", "## Non-claims", ""])
        lines.extend(f"- {c}" for c in self.non_claims)
        return "\n".join(lines) + "\n"


ReviewBundle = CryptanalysisReport


@dataclass(frozen=True)
class FileDigest:
    path: str
    sha256: str
    bytes: int

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def _surface_priority(sample_ratio: float, eta: float) -> str:
    if eta == 0.0:
        return "toy-only-noiseless"
    if sample_ratio > 1000 or eta < 2**-16:
        return "critical"
    if sample_ratio > 100 or eta < 2**-10:
        return "high"
    return "normal"


def collect_public_surfaces(params: SableParams, *, input_ciphertexts: int = 1000) -> list[ReviewSurface]:
    n_exp = params.N * params.N
    n_cmp = params.N * params.m_c
    n_diff = params.N * (params.m_c * (params.m_c - 1) // 2)
    eta_diff = ((params.q - 1.0) / params.q) * (1.0 - (1.0 - params.q * params.eta_c / (params.q - 1.0)) ** 2)
    return [
        ReviewSurface("expansion_key_sparse_lpn_rows", "sparse q-ary LPN", params.n, params.q, params.eta, n_exp, params.k, n_exp / max(1, params.n), params.eta * n_exp, _surface_priority(n_exp / max(1, params.n), params.eta), "GSW-style expansion key rows under the nonlinear evaluation secret."),
        ReviewSurface("compaction_key_qary_lpn_rows", "dense q-ary LPN / code decoding", params.n_c, params.q, params.eta_c, n_cmp, None, n_cmp / max(1, params.n_c), params.eta_c * n_cmp, _surface_priority(n_cmp / max(1, params.n_c), params.eta_c), "Coordinate compaction key rows under the CLPN secret."),
        ReviewSurface("same_entry_compaction_row_differences", "derived q-ary LPN row differences", params.n_c, params.q, eta_diff, n_diff, None, n_diff / max(1, params.n_c), eta_diff * n_diff, _surface_priority(n_diff / max(1, params.n_c), eta_diff), "Within-entry CLPN row differences cancel the encrypted coordinate and expose two-term-noise LPN-like rows."),
        ReviewSurface("input_ciphertext_sparse_lpn_rows", "sparse q-ary LPN", params.n, params.q, params.eta, input_ciphertexts * params.replicas, params.k, (input_ciphertexts * params.replicas) / max(1, params.n), params.eta * input_ciphertexts * params.replicas, _surface_priority((input_ciphertexts * params.replicas) / max(1, params.n), params.eta), "Application-dependent encrypted input traffic."),
    ]


enumerate_public_surfaces = collect_public_surfaces


def build_review_bundle(params: SableParams, *, depth: int = 1, additions: int = 1, target_bits: float = 128.0, input_ciphertexts: int = 1000, relation_screen_weight: int = 3, seed: int = 2026) -> CryptanalysisReport:
    surfaces = collect_public_surfaces(params, input_ciphertexts=input_ciphertexts)
    correctness = estimate(params, depth=depth, additions=additions, target_bits=target_bits)
    relation = estimate_c7_relations(params, mode="coordinate", relation_screen_weight=relation_screen_weight, target_bits=target_bits, seed=seed).to_jsonable()
    screens: list[dict[str, Any]] = []
    blockers: list[str] = []
    finite_bits: list[float] = []
    for surface in surfaces:
        screen = estimate_qary_lpn_surface(name=surface.name, n=surface.secret_dimension, q=surface.q, eta=surface.noise_rate, samples=max(1, surface.public_samples), row_weight=surface.row_weight, target_bits=target_bits)
        screens.append(screen)
        bits = _parse_screen_bits(screen.get("conservative_min_bits"))
        if bits is not None and math.isfinite(bits):
            finite_bits.append(bits)
            if bits < target_bits:
                blockers.append(f"{surface.name} below target screen: {bits:.2f} bits")
        for warning in screen.get("warnings", []):
            text = str(warning)
            if any(key in text.lower() for key in ["zero", "below", "low", "large public", "sample"]):
                blockers.append(f"{surface.name}: {text}")
    rel_bits = _parse_screen_bits(relation.get("minimum_screen_bits"))
    if rel_bits is not None and math.isfinite(rel_bits):
        finite_bits.append(rel_bits)
        if rel_bits < target_bits:
            blockers.append(f"relation screen below target: {rel_bits:.2f} bits")
    if relation.get("verdict") not in {"passes-c7-relation-screen", "coordinate-mode-no-block-relations"}:
        blockers.append(f"relation screen verdict: {relation.get('verdict')}")
    questions = [
        "Are sparse q-ary LPN parameters adequate for the expansion-key sample volume?",
        "Are q-ary LPN/code parameters adequate for the compaction-key sample volume and row-difference surface?",
        "Do BKW-family, ISD-family, clean-subset, or low-noise attacks beat the target category?",
        "Does the proof account for all public samples in the t -> s -> r encrypted-secret chain?",
        "Do implementation choices such as seeding, serialization, tensor adapters, or fixed-point encoding change the distribution?",
    ]
    acceptance = [
        "At least two independent cryptanalysis reports find no attack below the target category on frozen parameter sets.",
        "A public issue tracker records all attacks, parameter failures, and responses.",
        "Frozen test vectors and parameter files reproduce all correctness and attack-screen results.",
        "The package maintains clear separation between standardized PQC wrapper services and experimental HE services.",
        "A hardened implementation plan exists before any sensitive-data deployment.",
    ]
    non_claims = [
        "This bundle does not certify SABLE-HE parameters as secure.",
        "This bundle is not a FIPS, CAVP, CMVP, ISO, or NIST algorithm validation.",
        "The Python implementation is not a constant-time production cryptographic module.",
    ]
    return CryptanalysisReport("sable-he-research", __version__, __release_name__, params.name, target_bits, "ready-for-independent-cryptanalysis", surfaces, correctness, relation, screens, min(finite_bits) if finite_bits else None, blockers, questions, acceptance, non_claims)


def format_review_bundle(bundle: CryptanalysisReport) -> str:
    lines = [f"SABLE-HE Phase 3 cryptanalysis bundle {bundle.version} ({bundle.release_name})", f"preset={bundle.preset} target={bundle.target_bits:g} status={bundle.status}", f"minimum finite screen bits={bundle.minimum_screen_bits if bundle.minimum_screen_bits is not None else 'n/a'}", "Public surfaces:"]
    for s in bundle.surfaces:
        rw = "dense" if s.row_weight is None else f"row_weight={s.row_weight}"
        lines.append(f"  - {s.name}: assumption={s.assumption_family}, n={s.secret_dimension}, q={s.q}, eta={s.noise_rate:g}, samples={s.public_samples}, {rw}, priority={s.review_priority}")
    if bundle.blockers:
        lines.append("Blockers / review notes:")
        lines.extend(f"  - {b}" for b in bundle.blockers[:40])
    lines.append("Next step: send JSON/Markdown bundle, code tag, and paper to independent reviewers.")
    return "\n".join(lines)


generate_report = build_review_bundle
format_report = format_review_bundle
phase3_surface_report = lambda params, target_bits=128.0: build_review_bundle(params, target_bits=target_bits).to_jsonable()


def collect_manifest(root: str | Path = ".") -> list[FileDigest]:
    root = Path(root).resolve()
    skip = {".git", "__pycache__", "build", "dist", ".pytest_cache", "paper", "audits"}
    suffixes = {".py", ".md", ".toml", ".txt", ".yml", ".yaml", ".json"}
    out: list[FileDigest] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in skip for part in path.parts):
            continue
        if path.suffix.lower() in suffixes or path.name in {"VERSION", "LICENSE", "Makefile"}:
            data = path.read_bytes()
            out.append(FileDigest(str(path.relative_to(root)), hashlib.sha256(data).hexdigest(), len(data)))
    return out


def disclosure_template() -> str:
    return """# SABLE-HE cryptanalysis disclosure template

## Summary
Briefly describe the distinguisher, key-recovery attack, correctness failure, side channel, or protocol weakness.

## Affected component
- [ ] Sparse-LPN input encryption
- [ ] GSW-style expansion/evaluation
- [ ] Code/LPN compaction
- [ ] Federated-learning aggregation API
- [ ] PQC wrapper/envelope
- [ ] Serialization or CLI

## Parameters and sample surface
List q, n, k, eta, n_c, m_c, eta_c, replicas, sample counts, and workload assumptions.

## Attack method
Describe the algorithm, complexity model, memory, required samples, and whether it is classical or quantum.

## Reproduction
Provide code, commands, seeds, challenge vectors, and expected outputs.

## Impact
Explain what is recovered or distinguished and whether the attack breaks privacy, correctness, authentication, or implementation safety.

## Suggested mitigation
Optional: parameter changes, design changes, proof correction, implementation hardening, or documentation updates.
"""


def _write_public_surfaces_csv(path: Path, surfaces: list[ReviewSurface]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(surfaces[0].to_jsonable()))
        writer.writeheader()
        for surface in surfaces:
            writer.writerow(surface.to_jsonable())


def write_review_bundle(output_dir: str | Path, *, preset: str = "c7_standard_toy_noisy", depth: int = 1, additions: int = 1, target_bits: float = 128.0, input_ciphertexts: int = 1000, seed: int = 2026) -> dict[str, str]:
    if preset not in PRESETS:
        raise KeyError(f"unknown preset: {preset}")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bundle = build_review_bundle(PRESETS[preset], depth=depth, additions=additions, target_bits=target_bits, input_ciphertexts=input_ciphertexts, seed=seed)
    report_json = out / f"sable_cryptanalysis_bundle_{preset}.json"
    report_md = out / f"sable_cryptanalysis_bundle_{preset}.md"
    params_json = out / "parameters.json"
    surfaces_csv = out / "public_surfaces.csv"
    questions_md = out / "QUESTIONS.md"
    reproduce = out / "REPRODUCE.sh"
    disclosure = out / "CRYPTANALYSIS_DISCLOSURE_TEMPLATE.md"
    report_json.write_text(json.dumps(bundle.to_jsonable(), indent=2, default=str) + "\n")
    report_md.write_text(bundle.to_markdown())
    params_json.write_text(json.dumps(asdict(PRESETS[preset]), indent=2) + "\n")
    _write_public_surfaces_csv(surfaces_csv, bundle.surfaces)
    questions_md.write_text("# Reviewer questions\n\n" + "\n".join(f"- {q}" for q in bundle.mandatory_review_questions) + "\n")
    disclosure.write_text(disclosure_template())
    reproduce.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\nsable-he cryptanalysis-info --preset {preset} --target-bits {target_bits:g} --json > reproduced_report.json\n")
    reproduce.chmod(0o755)
    (out / "README.md").write_text(f"# SABLE-HE Phase 3 Independent Cryptanalysis Bundle\n\nPreset: `{preset}`\n\nThis bundle is for external review. It does not certify security.\n")
    return {"directory": str(out), "json": str(report_json), "markdown": str(report_md), "parameters": str(params_json), "surfaces": str(surfaces_csv), "questions": str(questions_md), "disclosure_template": str(disclosure)}


def write_phase3_bundle(root: str | Path, params: SableParams, *, target_bits: float = 128.0, seed: int = 2026, challenge_samples: int = 64) -> dict[str, str]:
    del challenge_samples
    return write_review_bundle(root, preset=params.name, target_bits=target_bits, seed=seed)


def render_surface_markdown(report: CryptanalysisReport | dict[str, Any]) -> str:
    if isinstance(report, CryptanalysisReport):
        return report.to_markdown()
    return json.dumps(report, indent=2, default=str) + "\n"


__all__ = [
    "ATTACK_FAMILIES", "REVIEW_SCOPE", "ReviewSurface", "CryptanalysisSurface", "CryptanalysisReport", "ReviewBundle", "FileDigest",
    "collect_public_surfaces", "enumerate_public_surfaces", "collect_manifest", "build_review_bundle", "write_review_bundle", "write_phase3_bundle",
    "generate_report", "format_report", "format_review_bundle", "phase3_surface_report", "render_surface_markdown", "disclosure_template",
]

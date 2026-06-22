"""Phase 5 standardization and external-review utilities.

This module prepares public, non-confidential review packages for SABLE-HE.
It does not certify parameters, does not claim NIST/ISO/HE.org approval, and
keeps SABLE-HE positioned as a post-quantum code/LPN-based HE research system.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .version import __version__, __release_name__
from .params import PRESETS, SableParams
from .cryptanalysis import attack_surface_report, challenge_info, red_team_template

SCHEMA = "sable-standardization-review-v1"


@dataclass(frozen=True)
class StandardizationItem:
    area: str
    status: str
    evidence: str
    next_action: str


@dataclass(frozen=True)
class ParameterTemplate:
    name: str
    security_target_bits: int
    q: int
    n: int
    k: int
    eta: float
    n_c: int
    m_c: int
    eta_c: float
    depth: int
    additions: int
    replicas: int
    intended_use: str
    required_external_review: list[str]

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def standardization_info() -> dict[str, Any]:
    """Return Phase 5 status and scope."""
    return {
        "schema": SCHEMA,
        "package": "sable-he-research",
        "version": __version__,
        "release_name": __release_name__,
        "phase": "Phase 5: standardization and external review preparation",
        "status": "ready-for-external-review-package-generation",
        "correct_claim": "post-quantum code/LPN-based leveled HE research implementation",
        "not_claimed": [
            "NIST-standardized homomorphic encryption",
            "FIPS 140-3 validated module",
            "certified secure SABLE-HE parameters",
            "production cryptographic boundary",
            "full FHE or bootstrapped HE",
        ],
        "review_targets": [
            "sparse q-ary LPN assumption and sample counts",
            "q-ary code/LPN compaction assumptions",
            "public evaluation-key and compaction-key sample surfaces",
            "correctness/noise-growth bounds for low-depth circuits",
            "relation-resistant coordinate compaction",
            "fixed-point encrypted FedAvg workflow",
            "PQC wrapper boundary and demo-provider limitations",
        ],
        "recommended_external_venues": [
            "IACR preprint and cryptology review",
            "homomorphic encryption standardization community discussion",
            "post-quantum cryptography/security workshop review",
            "federated learning privacy/security artifact review",
            "independent implementation/security audit",
        ],
    }


def readiness_matrix() -> list[StandardizationItem]:
    return [
        StandardizationItem(
            "scheme specification",
            "amber",
            "Public algorithms and docs exist; paper/spec should be frozen before formal submission.",
            "Publish a versioned, standalone specification and attach exact code tag.",
        ),
        StandardizationItem(
            "security assumptions",
            "amber",
            "Sparse q-ary LPN and q-ary code/LPN assumptions are explicit.",
            "Obtain independent review of parameter regimes, sample surfaces, and low-noise attacks.",
        ),
        StandardizationItem(
            "concrete parameters",
            "red",
            "Toy/research presets exist but are not certified secure.",
            "Develop 128/192/256-bit candidate templates with specialist attack-cost estimates.",
        ),
        StandardizationItem(
            "implementation",
            "amber",
            "Python reference package, KATs, and CLI checks exist.",
            "Build a memory-safe native core and bind Python only as a high-level interface.",
        ),
        StandardizationItem(
            "external cryptanalysis",
            "red",
            "Review bundles can be generated, but independent reports are not yet collected.",
            "Invite cryptanalysts and maintain a public disclosure/review log.",
        ),
        StandardizationItem(
            "supply-chain hygiene",
            "amber",
            "Clean public repo, release checks, and KATs exist.",
            "Adopt Trusted Publishing/attestations and pinned CI action versions.",
        ),
        StandardizationItem(
            "certification",
            "red",
            "No recognized validation path exists for SABLE-HE as a new HE primitive.",
            "Keep SABLE-HE outside certified boundary; use approved PQC/AES/SHA modules for production boundaries.",
        ),
    ]


def readiness_report() -> dict[str, Any]:
    items = [asdict(x) for x in readiness_matrix()]
    status_order = {"green": 0, "amber": 1, "red": 2}
    worst = max(items, key=lambda x: status_order.get(x["status"], 1))["status"]
    return {
        "schema": SCHEMA,
        "version": __version__,
        "overall_status": "pre-standardization-review" if worst in {"amber", "red"} else "ready",
        "items": items,
    }


def security_assumptions_spec() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "version": __version__,
        "assumptions": [
            {
                "name": "sparse q-ary LPN pseudorandomness",
                "used_for": ["compact input encryption", "GSW-style expansion key rows"],
                "parameters": ["q", "n", "k", "eta", "public_sample_count"],
                "review_questions": [
                    "What is the best known classical/quantum distinguishing cost for the chosen sparse distribution?",
                    "Does the public evaluation key create exploitable multi-sample structure?",
                    "Is the low-noise region compatible with correctness and security?",
                ],
            },
            {
                "name": "q-ary LPN / code-decoding semantic security",
                "used_for": ["relation-resistant coordinate compaction"],
                "parameters": ["q", "n_c", "m_c", "eta_c", "code", "public_sample_count"],
                "review_questions": [
                    "Do row-difference surfaces produce easier instances?",
                    "Are repetition-code prototypes replaced by paper-grade q-ary codes for candidate parameters?",
                    "What are the best ISD/BKW/low-noise attacks for each candidate?",
                ],
            },
            {
                "name": "PQC wrapper boundary",
                "used_for": ["transport/key-management labels and envelope metadata"],
                "parameters": ["ML-KEM label", "ML-DSA label", "AEAD", "hash"],
                "review_questions": [
                    "Is the selected backend a reviewed implementation?",
                    "Is the demo provider disabled in production?",
                    "Is SABLE-HE kept outside certified cryptographic boundaries?",
                ],
            },
        ],
    }


def parameter_template(preset: str = "c7_standard_toy_noisy", target_bits: int = 128, depth: int = 1) -> ParameterTemplate:
    p: SableParams = PRESETS[preset]
    return ParameterTemplate(
        name=f"candidate_template_from_{preset}",
        security_target_bits=target_bits,
        q=p.q,
        n=p.n,
        k=p.k,
        eta=p.eta,
        n_c=p.n_c,
        m_c=p.m_c,
        eta_c=p.eta_c,
        depth=depth,
        additions=1,
        replicas=p.replicas,
        intended_use="external-review template only; not a certified secure parameter set",
        required_external_review=[
            "sparse q-ary LPN estimator",
            "q-ary LPN/code-decoding estimator",
            "large-sample public-surface analysis",
            "correctness failure analysis",
            "implementation side-channel review",
        ],
    )


def review_checklist() -> list[dict[str, str]]:
    return [
        {"category": "correctness", "question": "Are row-support and q-ary error bounds valid for each supported operation?"},
        {"category": "correctness", "question": "Do empirical KATs and randomized tests match the formal fixed-point/FedAvg semantics?"},
        {"category": "security", "question": "Are all public sample counts included in sparse-LPN and q-ary-LPN attack estimates?"},
        {"category": "security", "question": "Do relation-resistant coordinate compaction keys avoid low-weight public relation families?"},
        {"category": "security", "question": "Does the proof avoid circular encryption of a secret under itself?"},
        {"category": "parameters", "question": "Are candidate parameter sets separated from toy/demo presets?"},
        {"category": "implementation", "question": "Are random sampling, serialization, and decoding failures specified and testable?"},
        {"category": "implementation", "question": "Does the package clearly mark the demo PQC provider as non-secure?"},
        {"category": "standardization", "question": "Is the claim language limited to pre-standardization/external review?"},
        {"category": "standardization", "question": "Are NIST/HE.org references used only for positioning, not certification claims?"},
    ]


def review_package_manifest(presets: list[str] | None = None, depth: int = 1, target_bits: int = 128) -> dict[str, Any]:
    presets = presets or ["c7_standard_toy_noisy"]
    reports = {}
    for name in presets:
        reports[name] = attack_surface_report(PRESETS[name], depth=depth, target_bits=target_bits)
    return {
        "schema": SCHEMA,
        "version": __version__,
        "release_name": __release_name__,
        "status": "pre-standardization external review package",
        "standardization_info": standardization_info(),
        "readiness_report": readiness_report(),
        "security_assumptions": security_assumptions_spec(),
        "parameter_templates": {name: parameter_template(name, target_bits=target_bits, depth=depth).to_jsonable() for name in presets},
        "attack_surface_reports": reports,
        "review_checklist": review_checklist(),
        "cryptanalysis_scope": challenge_info(),
    }


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_markdown(path: Path, title: str, lines: list[str]) -> None:
    path.write_text("# " + title + "\n\n" + "\n".join(lines) + "\n", encoding="utf-8")


def write_review_package(output: str | Path, presets: list[str] | None = None, depth: int = 1, target_bits: int = 128) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    manifest = review_package_manifest(presets=presets, depth=depth, target_bits=target_bits)

    files: list[str] = []
    def add_json(name: str, payload: Any) -> None:
        p = out / name
        _write_json(p, payload)
        files.append(str(p))

    add_json("standardization_manifest.json", manifest)
    add_json("readiness_report.json", manifest["readiness_report"])
    add_json("security_assumptions.json", manifest["security_assumptions"])
    add_json("parameter_templates.json", manifest["parameter_templates"])
    add_json("attack_surface_reports.json", manifest["attack_surface_reports"])
    add_json("review_checklist.json", manifest["review_checklist"])

    # CSV checklist for reviewers.
    csv_path = out / "review_checklist.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["category", "question"])
        writer.writeheader()
        writer.writerows(manifest["review_checklist"])
    files.append(str(csv_path))

    _write_markdown(
        out / "README.md",
        "SABLE-HE Phase 5 External Review Package",
        [
            "This package is intended for independent cryptanalysis and pre-standardization discussion.",
            "It does not certify SABLE-HE parameters and does not claim NIST, ISO, or HE.org standardization.",
            "",
            "## Files",
            "- `standardization_manifest.json`: complete machine-readable package manifest.",
            "- `security_assumptions.json`: assumptions and reviewer questions.",
            "- `parameter_templates.json`: candidate-template structure; not certified parameters.",
            "- `attack_surface_reports.json`: built-in public surface reports for selected presets.",
            "- `review_checklist.csv/json`: reviewer checklist.",
            "- `CRYPTANALYSIS_DISCLOSURE_TEMPLATE.md`: template for reporting attacks or concerns.",
        ],
    )
    files.append(str(out / "README.md"))

    template = red_team_template()
    (out / "CRYPTANALYSIS_DISCLOSURE_TEMPLATE.md").write_text(template, encoding="utf-8")
    files.append(str(out / "CRYPTANALYSIS_DISCLOSURE_TEMPLATE.md"))

    manifest_out = {"schema": SCHEMA, "version": __version__, "output": str(out), "files": files, "status": "written"}
    _write_json(out / "package_files.json", manifest_out)
    files.append(str(out / "package_files.json"))
    return manifest_out


def standardization_text_summary() -> str:
    info = standardization_info()
    return (
        f"SABLE-HE Phase 5 standardization/external-review release {__version__}.\n"
        f"Status: {info['status']}.\n"
        "Correct claim: post-quantum code/LPN-based leveled HE research implementation.\n"
        "Not claimed: NIST/ISO/HE.org standardization, certified parameters, or production cryptographic boundary."
    )

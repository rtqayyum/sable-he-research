"""Independent cryptanalysis support tools for SABLE-HE.

This module generates reproducible attack-surface reports, known-answer vectors,
and review bundles for external cryptanalysis. It does not certify concrete
security parameters.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from . import operations as ops
from .attacks import attack_lines, sample_profile, security_report
from .c7_relation_screen import estimate_c7_relations
from .estimator import estimate
from .params import PRESETS, SableParams
from .sable import compact_c7, decrypt_c7, encrypt, expand, keygen_c7
from .version import __release_name__, __version__

SCHEMA = "sable-cryptanalysis-bundle-v1"
DEFAULT_REVIEW_PRESETS = ("c7_standard_toy_clean", "c7_standard_toy_noisy", "candidate_depth1_rough")


@dataclass(frozen=True)
class SurfaceSummary:
    preset: str
    q: int
    n: int
    k: int
    eta: float
    n_c: int
    m_c: int
    eta_c: float
    replicas: int
    expansion_key_rows: int
    clpn_row_difference_samples: int
    sparse_row_entropy_bits: float


@dataclass(frozen=True)
class ChallengeVector:
    schema: str
    package: str
    version: str
    preset: str
    q: int
    key_seed: int
    values: dict[str, int]
    results: dict[str, int]
    status: str


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "to_jsonable"):
        return obj.to_jsonable()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, float):
        if math.isinf(obj):
            return "inf" if obj > 0 else "-inf"
        if math.isnan(obj):
            return "nan"
    return str(obj)


def _json_dump(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=_json_default) + "\n", encoding="utf-8")


def surface_summary(params: SableParams) -> SurfaceSummary:
    profile = sample_profile(params)
    return SurfaceSummary(
        preset=params.name,
        q=params.q,
        n=params.n,
        k=params.k,
        eta=params.eta,
        n_c=params.n_c,
        m_c=params.m_c,
        eta_c=params.eta_c,
        replicas=params.replicas,
        expansion_key_rows=profile.gsw_rows,
        clpn_row_difference_samples=profile.clpn_difference_rows,
        sparse_row_entropy_bits=profile.sparse_row_entropy_bits,
    )


def challenge_info() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "package": "sable-he-research",
        "version": __version__,
        "release_name": __release_name__,
        "phase": "independent cryptanalysis package",
        "security_status": "research implementation; no certified secure parameter set",
        "primary_claim_for_review": "post-quantum code/LPN-based leveled HE candidate with relation-resistant coordinate compaction",
        "assumptions_to_review": [
            "sparse q-ary LPN pseudorandomness for compact input and expansion-key rows",
            "q-ary LPN/code pseudorandomness for the compaction layer",
            "sample-count safety for public evaluation keys and compaction keys",
            "relation-surface resistance of coordinate compaction",
        ],
        "public_surfaces": [
            "sparse-LPN input ciphertexts",
            "GSW-style sparse-LPN expansion-key matrices",
            "code/LPN compaction-key ciphertexts",
            "CLPN row-difference samples",
        ],
        "cryptanalysis_targets": [
            "clean-subset low-noise attacks",
            "information-set decoding / Prange-style attacks",
            "BKW-style q-ary LPN attacks",
            "large-sample distinguishers",
            "sparse-row structural distinguishers",
            "relation attacks on compaction keys",
            "implementation bugs in arithmetic, encoding, serialization, and randomness",
        ],
        "not_in_scope_for_certification": [
            "FIPS 140-3 module validation",
            "algorithm validation for SABLE-HE itself",
            "side-channel certification",
            "deployment-grade parameter certification",
        ],
    }


def attack_surface_report(
    params: SableParams,
    *,
    depth: int = 1,
    additions: int = 1,
    target_bits: int = 128,
    relation_mode: str = "standard",
    relation_screen_weight: int = 3,
) -> dict[str, Any]:
    arithmetic = estimate(params, depth=depth, additions=additions, target_bits=target_bits)
    relation = estimate_c7_relations(
        params,
        mode=relation_mode,
        relation_screen_weight=relation_screen_weight,
        target_bits=float(target_bits),
    )
    lines = [asdict(line) for line in attack_lines(params, target_bits=target_bits)]
    sec = security_report(params, target_bits=target_bits)
    blockers = list(arithmetic.get("warnings", [])) + list(relation.blockers)
    if not sec.get("passes_screen", False):
        blockers.append("built-in first-pass attack screen is below target")
    return {
        "schema": "sable-attack-surface-report-v1",
        "package": "sable-he-research",
        "version": __version__,
        "preset": params.name,
        "target_bits": target_bits,
        "depth": depth,
        "additions": additions,
        "surface_summary": asdict(surface_summary(params)),
        "correctness_and_size_estimate": arithmetic,
        "security_screen": sec,
        "attack_lines": lines,
        "relation_screen": relation.to_jsonable(),
        "blockers_and_notes": blockers,
        "verdict": "external-review-required" if blockers else "passes-internal-screens-only",
        "disclaimer": "Internal screening artifact only; not a security certificate.",
    }


def known_answer_vector(preset: str = "c7_standard_toy_clean", *, key_seed: int = 4040) -> ChallengeVector:
    params = PRESETS[preset]
    if params.eta != 0.0 or params.eta_c != 0.0:
        raise ValueError("known-answer vectors use a zero-noise preset for deterministic reproducibility")
    kp = keygen_c7(params, seed=key_seed, mode="coordinate")

    def enc(value: int, offset: int):
        return expand(kp, encrypt(kp, value % params.q, seed=key_seed + offset))

    x = 3 % params.q
    y = 5 % params.q
    z = 2 % params.q
    ct_x = enc(x, 11)
    ct_y = enc(y, 22)
    ct_z = enc(z, 33)
    ct_one = enc(1, 44)
    ct_zero = enc(0, 55)
    results = {
        "add_x_y": decrypt_c7(kp, compact_c7(kp, ops.add(ct_x, ct_y))),
        "sub_y_x": decrypt_c7(kp, compact_c7(kp, ops.sub(ct_y, ct_x))),
        "mul_x_y": decrypt_c7(kp, compact_c7(kp, ops.mul(ct_x, ct_y))),
        "square_x": decrypt_c7(kp, compact_c7(kp, ops.square(ct_x))),
        "quadratic_xy_plus_z": decrypt_c7(kp, compact_c7(kp, ops.add(ops.mul(ct_x, ct_y), ct_z))),
        "bool_xor_1_0": decrypt_c7(kp, compact_c7(kp, ops.gate_xor(ct_one, ct_zero))),
        "bool_and_1_0": decrypt_c7(kp, compact_c7(kp, ops.gate_and(ct_one, ct_zero))),
    }
    expected = {
        "add_x_y": (x + y) % params.q,
        "sub_y_x": (y - x) % params.q,
        "mul_x_y": (x * y) % params.q,
        "square_x": (x * x) % params.q,
        "quadratic_xy_plus_z": (x * y + z) % params.q,
        "bool_xor_1_0": 1,
        "bool_and_1_0": 0,
    }
    return ChallengeVector(
        schema="sable-known-answer-vector-v1",
        package="sable-he-research",
        version=__version__,
        preset=preset,
        q=params.q,
        key_seed=key_seed,
        values={"x": x, "y": y, "z": z, "one": 1, "zero": 0},
        results=results,
        status="pass" if results == expected else "fail",
    )


def red_team_template() -> str:
    return """# SABLE-HE cryptanalysis report

## Summary
- Reporter:
- Date:
- Package version:
- Commit/tag reviewed:
- Parameter preset(s):
- Attack family:
- Result severity: informational / low / medium / high / critical

## Claim being tested
State the exact security, correctness, implementation, or parameter claim being tested.

## Reproduction environment
```text
OS:
Python:
sable-he-research:
Command(s):
```

## Attack model
Describe the adversary, public material, sample counts, memory model, oracle access, and whether the estimate is classical, quantum, or both.

## Method
Describe the attack or distinguisher. Include formulas, pseudocode, scripts, or notebooks where possible.

## Results
Include work factor, memory, success probability, sample requirements, affected presets, and any transcripts or outputs.

## Impact
Explain whether the result breaks confidentiality, correctness, relation resistance, parameter claims, or implementation behavior.

## Suggested mitigation
Recommend parameter changes, proof changes, implementation changes, or claim wording changes.
"""


def write_challenge_bundle(
    output_dir: str | Path,
    *,
    presets: Iterable[str] | None = None,
    depths: Iterable[int] = (1,),
    target_bits: int = 128,
) -> dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    presets = list(presets or DEFAULT_REVIEW_PRESETS)
    reports_dir = out / "reports"
    reports_dir.mkdir(exist_ok=True)
    vectors_dir = out / "vectors"
    vectors_dir.mkdir(exist_ok=True)
    templates_dir = out / "templates"
    templates_dir.mkdir(exist_ok=True)
    _json_dump(out / "challenge_info.json", challenge_info())
    (templates_dir / "cryptanalysis_report_template.md").write_text(red_team_template(), encoding="utf-8")
    _json_dump(vectors_dir / "sable_known_answer_vector.json", known_answer_vector())
    written_reports: list[str] = []
    for preset in presets:
        if preset not in PRESETS:
            continue
        for depth in depths:
            report = attack_surface_report(PRESETS[preset], depth=int(depth), target_bits=target_bits)
            path = reports_dir / f"{preset}_depth{depth}_attack_surface.json"
            _json_dump(path, report)
            written_reports.append(str(path.relative_to(out)))
    with (out / "public_surface_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        fieldnames = list(asdict(surface_summary(PRESETS[presets[0]])).keys()) if presets and presets[0] in PRESETS else []
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for preset in presets:
            if preset in PRESETS:
                writer.writerow(asdict(surface_summary(PRESETS[preset])))
    readme = f"""# SABLE-HE cryptanalysis bundle

Package version: `{__version__}`  
Release: `{__release_name__}`

This bundle is designed for independent cryptanalysis and reproduction. It is not a security certificate.
"""
    (out / "README.md").write_text(readme, encoding="utf-8")
    manifest = {
        "schema": SCHEMA,
        "version": __version__,
        "files": [
            "README.md",
            "challenge_info.json",
            "public_surface_summary.csv",
            "vectors/sable_known_answer_vector.json",
            "templates/cryptanalysis_report_template.md",
            *written_reports,
        ],
    }
    _json_dump(out / "manifest.json", manifest)
    return manifest


ReviewSurface = SurfaceSummary
ReviewBundle = dict
build_review_bundle = attack_surface_report
enumerate_public_surfaces = lambda params, **_: [surface_summary(params)]
format_review_bundle = lambda bundle: json.dumps(bundle, indent=2, default=_json_default)
write_review_bundle = lambda output_dir, **kwargs: write_challenge_bundle(output_dir, **kwargs)

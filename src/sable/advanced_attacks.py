"""Phase 8 attack-estimator framework for SABLE-HE.

This module provides a stronger internal estimator layer for sparse q-ary LPN,
q-ary LPN/code, public-sample, and relation-derived surfaces.  The estimates are
screening tools for papers and external review packages.  They are not a
replacement for specialist LPN/ISD/BKW cryptanalysis and they do not certify any
parameter set.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .field import qary_piling_up
from .parameter_sets import CANDIDATES, CandidateParameterSet, candidate_names, get_candidate
from .version import __release_name__, __version__

SCHEMA = "sable-phase8-attack-estimator-v1"


@dataclass(frozen=True)
class PublicSurface:
    """A public noisy-linear-equation surface exposed by a candidate."""

    name: str
    assumption_family: str
    q: int
    dimension: int
    samples: int
    eta: float
    row_weight: int | None = None
    priority: str = "normal"
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackCost:
    """One attack-family cost estimate in bits."""

    surface: str
    attack: str
    bits: float
    model: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_jsonable(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class SurfaceEstimate:
    surface: PublicSurface
    costs: tuple[AttackCost, ...]
    minimum_bits: float
    blocker_notes: tuple[str, ...]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "surface": self.surface.to_jsonable(),
            "costs": [c.to_jsonable() for c in self.costs],
            "minimum_bits": _jsonable(self.minimum_bits),
            "blocker_notes": list(self.blocker_notes),
        }


@dataclass(frozen=True)
class CandidateAttackReport:
    candidate: str
    target_bits: int
    surfaces: tuple[SurfaceEstimate, ...]
    minimum_bits: float
    verdict: str
    blockers: tuple[str, ...]
    disclaimer: str = "Internal screening only; external expert cryptanalysis required."

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "version": __version__,
            "release_name": __release_name__,
            "candidate": self.candidate,
            "target_bits": self.target_bits,
            "surfaces": [s.to_jsonable() for s in self.surfaces],
            "minimum_bits": _jsonable(self.minimum_bits),
            "verdict": self.verdict,
            "blockers": list(self.blockers),
            "disclaimer": self.disclaimer,
        }


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, float):
        if math.isinf(obj):
            return "inf" if obj > 0 else "-inf"
        if math.isnan(obj):
            return "nan"
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, tuple):
        return [_jsonable(v) for v in obj]
    return obj


def _log2_add(a: float, b: float) -> float:
    if math.isinf(a):
        return b if a < 0 else a
    if math.isinf(b):
        return a if b < 0 else b
    m = max(a, b)
    if m == float("-inf"):
        return m
    return m + math.log2(2 ** (a - m) + 2 ** (b - m))


def _log2_sum(values: Iterable[float]) -> float:
    acc = float("-inf")
    for value in values:
        acc = _log2_add(acc, value)
    return acc


def _log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    if k == 0 or k == n:
        return 0.0
    k = min(k, n - k)
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)


def _neg_log2_one_minus(p: float) -> float:
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return float("inf")
    return -math.log2(1.0 - p)


def _safe_log2(x: float) -> float:
    if x <= 0.0:
        return float("-inf")
    return math.log2(x)


def qary_bias(q: int, eta: float) -> float:
    """Return the absolute nontrivial-character bias for q-ary symmetric noise."""

    if q <= 1:
        return 0.0
    return abs(1.0 - (q * eta) / (q - 1))


def clean_subset_bits(dimension: int, eta: float, algebra_factor: float = 2.8) -> float:
    """Cost proxy for selecting a clean information subset plus linear algebra."""

    return dimension * _neg_log2_one_minus(eta) + algebra_factor * math.log2(max(2, dimension))


def prange_isd_bits(samples: int, dimension: int, eta: float, algebra_factor: float = 2.8) -> float:
    """Prange-style ISD proxy using probability of a clean information set."""

    if samples <= dimension:
        return clean_subset_bits(dimension, eta, algebra_factor=algebra_factor)
    t = max(0, min(samples - dimension, int(round(samples * eta))))
    clean = samples - t
    if clean < dimension:
        return float("inf")
    return _log2_comb(samples, dimension) - _log2_comb(clean, dimension) + algebra_factor * math.log2(max(2, dimension))


def stern_proxy_bits(samples: int, dimension: int, eta: float, q: int) -> float:
    """Conservative Stern-style proxy.

    This is not a full Stern implementation.  It discounts Prange by a small
    collision/list factor and clamps at the clean-subset proxy.  The output is a
    red-flag screen, not a security proof.
    """

    base = prange_isd_bits(samples, dimension, eta)
    t = max(1, int(round(samples * eta)))
    split = max(1, min(t // 2, dimension // 4 if dimension >= 4 else 1))
    list_gain = min(0.25 * _log2_comb(max(2, dimension // 2), split), 0.20 * base if math.isfinite(base) else 0.0)
    q_penalty = 0.5 * math.log2(max(2, q))
    return max(0.0, base - list_gain + q_penalty)


def dumer_proxy_bits(samples: int, dimension: int, eta: float, q: int) -> float:
    """Dumer-style ISD proxy with a slightly larger list-merging gain."""

    base = prange_isd_bits(samples, dimension, eta)
    t = max(1, int(round(samples * eta)))
    split = max(1, min(t // 3, dimension // 6 if dimension >= 6 else 1))
    list_gain = min(0.35 * _log2_comb(max(2, dimension // 2), split), 0.30 * base if math.isfinite(base) else 0.0)
    q_penalty = math.log2(max(2, q))
    return max(0.0, base - list_gain + q_penalty)


def may_ozerov_proxy_bits(samples: int, dimension: int, eta: float, q: int) -> float:
    """Nearest-neighbour ISD proxy inspired by modern ISD families."""

    base = dumer_proxy_bits(samples, dimension, eta, q)
    nn_gain = min(0.08 * max(1.0, dimension), 0.15 * base if math.isfinite(base) else 0.0)
    return max(0.0, base - nn_gain)


def bkw_scan(q: int, dimension: int, samples: int, eta: float, *, max_block: int = 16) -> dict[str, Any]:
    """Scan a simple q-ary BKW-style table/sample proxy.

    The scan varies block width and number of reduction levels.  It accounts for
    table sizes, available samples, and q-ary noise bias after repeated sample
    additions.  The smallest row is a screening estimate only.
    """

    beta = max(1e-300, qary_bias(q, eta))
    candidates: list[dict[str, Any]] = []
    block_choices = sorted({1, 2, 3, 4, 6, 8, 12, 16, max(1, min(max_block, dimension))})
    for block_width in block_choices:
        if block_width > max_block or block_width > dimension:
            continue
        max_levels = max(1, min(32, math.ceil(dimension / block_width)))
        for levels in range(1, max_levels + 1):
            reduced = max(0, dimension - levels * block_width)
            combinations = 2 ** levels
            bias_after = beta ** combinations
            distinguishing_samples_bits = 2.0 * max(0.0, -_safe_log2(bias_after))
            available_samples_bits = math.log2(max(1, samples))
            if distinguishing_samples_bits > available_samples_bits + 8:
                sample_penalty = distinguishing_samples_bits - available_samples_bits
            else:
                sample_penalty = 0.0
            table_bits = math.log2(max(1, levels)) + block_width * math.log2(max(2, q))
            residual_bits = max(0, reduced) * 0.15
            total_bits = _log2_sum([table_bits, distinguishing_samples_bits, residual_bits]) + sample_penalty
            candidates.append({
                "block_width": block_width,
                "levels": levels,
                "remaining_dimension": reduced,
                "table_bits": table_bits,
                "distinguishing_samples_bits": distinguishing_samples_bits,
                "available_samples_bits": available_samples_bits,
                "sample_penalty_bits": sample_penalty,
                "residual_bits": residual_bits,
                "total_bits": total_bits,
                "bias_after_reduction": bias_after if bias_after > 1e-300 else 0.0,
            })
    best = min(candidates, key=lambda row: row["total_bits"]) if candidates else {"total_bits": float("inf")}
    return {"best": _jsonable(best), "scan_count": len(candidates), "model": "q-ary BKW table/sample/bias screen; not a specialist implementation"}


def surfaces_for_candidate(candidate: CandidateParameterSet | str, *, fl_clients: int = 100, model_length: int = 1000) -> tuple[PublicSurface, ...]:
    c = get_candidate(candidate) if isinstance(candidate, str) else candidate
    N = c.N
    rowdiff_eta = qary_piling_up(c.q, c.eta_c, 2)
    return (
        PublicSurface(
            "expansion_key_sparse_lpn_rows",
            "sparse q-ary LPN / GSW expansion rows",
            c.q,
            c.n,
            N * N,
            c.eta,
            row_weight=c.k,
            priority="critical",
            notes=("public expansion key", "sparse row distribution"),
        ),
        PublicSurface(
            "compaction_key_qary_lpn_rows",
            "dense q-ary LPN/code compaction rows",
            c.q,
            c.n_c,
            N * c.m_c,
            c.eta_c,
            row_weight=None,
            priority="critical",
            notes=("public compaction key", "same secret across rows"),
        ),
        PublicSurface(
            "same_entry_compaction_row_differences",
            "derived q-ary LPN row-difference surface",
            c.q,
            c.n_c,
            N * (c.m_c * (c.m_c - 1) // 2),
            rowdiff_eta,
            row_weight=None,
            priority="critical",
            notes=("message-cancelling CLPN row differences", "two-term q-ary noise"),
        ),
        PublicSurface(
            "input_ciphertext_sparse_lpn_rows",
            "deployment input sparse q-ary LPN rows",
            c.q,
            c.n,
            fl_clients * model_length,
            c.eta,
            row_weight=c.k,
            priority="high",
            notes=("deployment-dependent", f"clients={fl_clients}", f"model_length={model_length}"),
        ),
    )


def estimate_surface(surface: PublicSurface, target_bits: int) -> SurfaceEstimate:
    costs: list[AttackCost] = []
    clean = clean_subset_bits(surface.dimension, surface.eta)
    costs.append(AttackCost(surface.name, "clean-subset", clean, "clean information subset plus linear algebra", "screen"))
    prange = prange_isd_bits(surface.samples, surface.dimension, surface.eta)
    costs.append(AttackCost(surface.name, "prange-isd", prange, "Prange-style clean information set", "screen", {"samples": surface.samples}))
    stern = stern_proxy_bits(surface.samples, surface.dimension, surface.eta, surface.q)
    costs.append(AttackCost(surface.name, "stern-isd-proxy", stern, "Stern-style list/collision proxy", "screen"))
    dumer = dumer_proxy_bits(surface.samples, surface.dimension, surface.eta, surface.q)
    costs.append(AttackCost(surface.name, "dumer-isd-proxy", dumer, "Dumer-style list-merging proxy", "screen"))
    mo = may_ozerov_proxy_bits(surface.samples, surface.dimension, surface.eta, surface.q)
    costs.append(AttackCost(surface.name, "may-ozerov-isd-proxy", mo, "nearest-neighbour ISD proxy", "screen"))
    bkw = bkw_scan(surface.q, surface.dimension, surface.samples, surface.eta)
    costs.append(AttackCost(surface.name, "qary-bkw-scan", float(bkw["best"].get("total_bits", float("inf"))), bkw["model"], "screen", bkw))

    finite = [c.bits for c in costs if math.isfinite(c.bits)]
    minimum = min(finite) if finite else float("inf")
    blockers: list[str] = []
    if minimum < target_bits:
        blockers.append(f"minimum internal screen below target ({minimum:.2f} < {target_bits})")
    if surface.samples >= surface.dimension:
        blockers.append("public samples at least as many as secret dimension; specialist multi-sample analysis required")
    if surface.samples > 100 * max(1, surface.dimension):
        blockers.append("large sample-to-dimension ratio; derived-sample attacks require review")
    if surface.row_weight is not None and surface.row_weight <= 2:
        blockers.append("very sparse rows; sparse-LPN structural/collision screens required")
    return SurfaceEstimate(surface, tuple(costs), minimum, tuple(blockers))


def estimate_candidate(candidate: CandidateParameterSet | str, *, fl_clients: int = 100, model_length: int = 1000, target_bits: int | None = None) -> CandidateAttackReport:
    c = get_candidate(candidate) if isinstance(candidate, str) else candidate
    target = target_bits or c.target_bits
    surfaces = tuple(estimate_surface(surface, target) for surface in surfaces_for_candidate(c, fl_clients=fl_clients, model_length=model_length))
    finite = [s.minimum_bits for s in surfaces if math.isfinite(s.minimum_bits)]
    minimum = min(finite) if finite else float("inf")
    blockers: list[str] = []
    for surface in surfaces:
        blockers.extend(f"{surface.surface.name}: {note}" for note in surface.blocker_notes)
    verdict = "passes-internal-advanced-screens-only" if minimum >= target and not blockers else "requires-external-cryptanalysis"
    return CandidateAttackReport(c.name, target, surfaces, minimum, verdict, tuple(blockers))


def phase8_info() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "package": "sable-he-research",
        "version": __version__,
        "release_name": __release_name__,
        "phase": "Phase 8 stronger internal LPN/ISD/BKW attack-estimator framework",
        "status": "internal screening and external-review support; not expert certification",
        "scope": [
            "surface-specific sparse q-ary LPN and q-ary LPN accounting",
            "clean-subset screens",
            "Prange-style ISD screens",
            "Stern/Dumer/May-Ozerov-inspired proxy screens",
            "q-ary BKW block-width/level scan",
            "CSV/JSON/Markdown attack packages for external reviewers",
        ],
        "important_warning": "These estimates are internal screens. The word expert requires independent cryptanalysts.",
        "candidates": candidate_names(),
        "not_claimed": ["certified parameters", "NIST/FIPS validation", "independent cryptanalysis", "deployment guidance"],
    }


def format_surface_estimate(surface: SurfaceEstimate) -> str:
    lines = [f"Surface: {surface.surface.name}", f"  assumption={surface.surface.assumption_family}", f"  q={surface.surface.q} dimension={surface.surface.dimension} samples={surface.surface.samples} eta={surface.surface.eta}"]
    if surface.surface.row_weight is not None:
        lines.append(f"  row_weight={surface.surface.row_weight}")
    lines.append(f"  minimum_bits={surface.minimum_bits:.2f}")
    for cost in surface.costs:
        lines.append(f"    - {cost.attack:<24} {cost.bits:.2f} bits ({cost.status})")
    if surface.blocker_notes:
        lines.append("  notes:")
        for note in surface.blocker_notes:
            lines.append(f"    * {note}")
    return "\n".join(lines)


def format_candidate_attack_report(report: CandidateAttackReport) -> str:
    lines = [
        f"SABLE-HE Phase 8 advanced attack estimate for {report.candidate}",
        f"target_bits={report.target_bits} minimum_internal_screen_bits={report.minimum_bits:.2f}",
        f"verdict={report.verdict}",
        "",
    ]
    for surface in report.surfaces:
        lines.append(format_surface_estimate(surface))
        lines.append("")
    if report.blockers:
        lines.append("Blockers / external-review prompts:")
        for blocker in report.blockers:
            lines.append(f"  - {blocker}")
    lines.append(report.disclaimer)
    return "\n".join(lines)


def write_attack_package(output: str | Path, names: Iterable[str] | None = None, *, fl_clients: int = 100, model_length: int = 1000, target_bits: int | None = None) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    selected = list(names) if names is not None else candidate_names()
    reports = {name: estimate_candidate(name, fl_clients=fl_clients, model_length=model_length, target_bits=target_bits).to_jsonable() for name in selected}
    (out / "phase8_attack_estimator_info.json").write_text(json.dumps(phase8_info(), indent=2, sort_keys=True, default=_jsonable) + "\n", encoding="utf-8")
    (out / "candidate_attack_reports.json").write_text(json.dumps(reports, indent=2, sort_keys=True, default=_jsonable) + "\n", encoding="utf-8")
    rows: list[dict[str, Any]] = []
    for name, report in reports.items():
        for surface in report["surfaces"]:
            for cost in surface["costs"]:
                rows.append({
                    "candidate": name,
                    "surface": surface["surface"]["name"],
                    "attack": cost["attack"],
                    "bits": cost["bits"],
                    "model": cost["model"],
                    "status": cost["status"],
                })
    with (out / "attack_costs.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["candidate", "surface", "attack", "bits", "model", "status"])
        writer.writeheader(); writer.writerows(rows)
    readme_lines = [
        "# SABLE-HE Phase 8 attack-estimator package",
        "",
        "This bundle contains stronger internal LPN/ISD/BKW screening outputs.",
        "It is intended for external cryptanalysis and paper review, not certification.",
        "",
        "| candidate | target | minimum bits | verdict |",
        "|---|---:|---:|---|",
    ]
    for name, report in reports.items():
        readme_lines.append(f"| {name} | {report['target_bits']} | {float(report['minimum_bits']):.2f} | {report['verdict']} |")
    readme_lines.extend([
        "",
        "## Required external checks",
        "",
        "1. Replace proxy ISD rows with specialist Prange/Stern/Dumer/BJMM/May-Ozerov estimators.",
        "2. Validate q-ary BKW screens for each public sample surface.",
        "3. Check sparse-row distributions and relation-derived surfaces.",
        "4. Audit sample-count assumptions against real deployment sizes.",
    ])
    (out / "README.md").write_text("\n".join(readme_lines) + "\n", encoding="utf-8")
    questions = """# Phase 8 external attack-estimator questions\n\n1. Are the q-ary BKW sample/bias assumptions too optimistic or too conservative?\n2. Which ISD family gives the strongest estimate for each SABLE surface?\n3. Do sparse row distributions create attacks not captured by dense ISD models?\n4. Do CLPN row-difference surfaces leak additional algebraic structure?\n5. Which candidate rows should be rejected before publication?\n"""
    (out / "ATTACK_REVIEW_QUESTIONS.md").write_text(questions, encoding="utf-8")
    manifest = {
        "schema": "sable-phase8-attack-package-v1",
        "version": __version__,
        "release_name": __release_name__,
        "candidate_count": len(selected),
        "candidates": selected,
        "files": sorted(p.name for p in out.iterdir() if p.is_file()),
        "output": str(out),
        "disclaimer": "Internal screens only; external expert review required.",
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest

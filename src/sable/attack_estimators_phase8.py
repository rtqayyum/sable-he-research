"""Phase 8 strengthened LPN/ISD/BKW attack-estimator framework.

This module provides reproducible *screening* estimates for the public surfaces
exposed by SABLE-HE candidate parameters.  It is deliberately conservative and
transparent: formulas are documented and every report carries a disclaimer that
external sparse-LPN/q-ary-LPN/ISD/BKW specialist review is required before any
security claim.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import parameter_sets
from .version import __release_name__, __version__

SCHEMA = "sable-phase8-strengthened-attack-estimator-v1"
OMEGA = 2.8


def _safe_log2(x: float) -> float:
    if x <= 0:
        return float("inf")
    return math.log2(x)


def _log2_add(a: float, b: float) -> float:
    if math.isinf(a):
        return b
    if math.isinf(b):
        return a
    m = max(a, b)
    return m + math.log2(2 ** (a - m) + 2 ** (b - m))


def log2_binom(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def qary_bias(q: int, eta: float) -> float:
    return abs(1.0 - (q * eta) / (q - 1.0))


def qary_piling_probability(q: int, eta: float, terms: int) -> float:
    if terms <= 0:
        return 0.0
    return ((q - 1.0) / q) * (1.0 - (1.0 - (q * eta) / (q - 1.0)) ** terms)


@dataclass(frozen=True)
class AttackSurfaceSpec:
    name: str
    assumption_family: str
    q: int
    dimension: int
    samples: int
    eta: float
    row_weight: int | None = None
    relation_weight: int = 1
    priority: str = "normal"
    description: str = ""

    @property
    def effective_eta(self) -> float:
        if self.relation_weight <= 1:
            return self.eta
        return qary_piling_probability(self.q, self.eta, self.relation_weight)

    @property
    def sample_to_dimension(self) -> float:
        return self.samples / max(1, self.dimension)

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["effective_eta"] = self.effective_eta
        d["sample_to_dimension"] = self.sample_to_dimension
        return d


@dataclass(frozen=True)
class AttackModelEstimate:
    model: str
    bits_classical: float
    bits_quantum_proxy: float
    applicable: bool
    status: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        for key in ["bits_classical", "bits_quantum_proxy"]:
            v = d[key]
            if math.isinf(v):
                d[key] = "inf"
            elif math.isnan(v):
                d[key] = "nan"
        return d


@dataclass(frozen=True)
class SurfaceAttackReport:
    surface: AttackSurfaceSpec
    estimates: tuple[AttackModelEstimate, ...]
    min_classical_bits: float
    min_quantum_proxy_bits: float
    verdict: str
    blockers: tuple[str, ...]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "surface": self.surface.to_jsonable(),
            "estimates": [e.to_jsonable() for e in self.estimates],
            "min_classical_bits": self.min_classical_bits if not math.isinf(self.min_classical_bits) else "inf",
            "min_quantum_proxy_bits": self.min_quantum_proxy_bits if not math.isinf(self.min_quantum_proxy_bits) else "inf",
            "verdict": self.verdict,
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True)
class CandidateAttackReport:
    schema: str
    version: str
    release_name: str
    candidate: str
    target_bits: int
    surface_reports: tuple[SurfaceAttackReport, ...]
    global_min_classical_bits: float
    global_min_quantum_proxy_bits: float
    overall_verdict: str
    caveats: tuple[str, ...]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "release_name": self.release_name,
            "candidate": self.candidate,
            "target_bits": self.target_bits,
            "surface_reports": [s.to_jsonable() for s in self.surface_reports],
            "global_min_classical_bits": self.global_min_classical_bits if not math.isinf(self.global_min_classical_bits) else "inf",
            "global_min_quantum_proxy_bits": self.global_min_quantum_proxy_bits if not math.isinf(self.global_min_quantum_proxy_bits) else "inf",
            "overall_verdict": self.overall_verdict,
            "caveats": list(self.caveats),
        }


def attack_estimator_info() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "version": __version__,
        "release_name": __release_name__,
        "status": "strengthened-internal-estimator; not expert-validated cryptanalysis",
        "models": [
            "no-clean-subset / low-noise screen",
            "Prange information-set-decoding proxy",
            "Stern-Dumer style ISD improvement proxy",
            "q-ary block-BKW scan",
            "generic exhaustive-secret lower bound",
            "large-sample surface and row-entropy diagnostics",
        ],
        "non_goals": [
            "certifying parameter sets",
            "replacing specialist LPN/ISD/BKW analysis",
            "claiming asymptotically tight attack complexity",
            "modeling every implementation-level algebraic relation",
        ],
    }


def attack_estimator_summary_text() -> str:
    info = attack_estimator_info()
    lines = [f"SABLE-HE Phase 8 estimator framework {info['version']} ({info['release_name']})"]
    lines.append(f"status={info['status']}")
    lines.append("Models:")
    for model in info["models"]:
        lines.append(f"  - {model}")
    lines.append("Non-goals:")
    for item in info["non_goals"]:
        lines.append(f"  - {item}")
    return "\n".join(lines)


def clean_subset_estimate(surface: AttackSurfaceSpec) -> AttackModelEstimate:
    n = surface.dimension
    eta = surface.effective_eta
    if eta <= 0:
        bits = OMEGA * math.log2(max(2, n))
        status = "zero-noise-degenerate"
    elif eta >= 1:
        bits = float("inf")
        status = "all-noise-not-modeled"
    else:
        bits = -n * math.log2(1.0 - eta) + OMEGA * math.log2(max(2, n))
        status = "finite"
    return AttackModelEstimate(
        model="no_clean_subset_low_noise_screen",
        bits_classical=bits,
        bits_quantum_proxy=max(0.0, 0.5 * bits),
        applicable=True,
        status=status,
        details={"dimension": n, "eta_effective": eta, "linear_algebra_exponent": OMEGA},
    )


def prange_estimate(surface: AttackSurfaceSpec) -> AttackModelEstimate:
    m = surface.samples
    n = surface.dimension
    eta = surface.effective_eta
    if m < n:
        return AttackModelEstimate(
            model="prange_isd_proxy",
            bits_classical=float("inf"),
            bits_quantum_proxy=float("inf"),
            applicable=False,
            status="sample-limited-m-less-than-n",
            details={"samples": m, "dimension": n},
        )
    t = min(m, max(0, int(round(eta * m))))
    clean_positions = max(0, m - t)
    if clean_positions < n:
        bits = float("inf")
        status = "too-many-errors-for-clean-information-set"
    else:
        bits = log2_binom(m, n) - log2_binom(clean_positions, n) + OMEGA * math.log2(max(2, n))
        status = "finite"
    return AttackModelEstimate(
        model="prange_isd_proxy",
        bits_classical=bits,
        bits_quantum_proxy=max(0.0, 0.5 * bits) if not math.isinf(bits) else bits,
        applicable=True,
        status=status,
        details={"samples": m, "dimension": n, "expected_errors": eta * m, "rounded_errors": t},
    )


def stern_dumer_proxy_estimate(surface: AttackSurfaceSpec) -> AttackModelEstimate:
    pr = prange_estimate(surface)
    if not pr.applicable or math.isinf(pr.bits_classical):
        return AttackModelEstimate(
            model="stern_dumer_isd_proxy",
            bits_classical=pr.bits_classical,
            bits_quantum_proxy=pr.bits_quantum_proxy,
            applicable=pr.applicable,
            status="inherits-prange-sample-limit",
            details=dict(pr.details),
        )
    n = surface.dimension
    m = surface.samples
    eta = surface.effective_eta
    # Conservative heuristic improvement over Prange.  This is not a specialist
    # estimator; it is a screen to force review of candidate surfaces.
    expected_errors = eta * m
    improvement = min(0.18 * n, 0.35 * expected_errors, 64.0)
    bits = max(0.0, pr.bits_classical - improvement)
    return AttackModelEstimate(
        model="stern_dumer_isd_proxy",
        bits_classical=bits,
        bits_quantum_proxy=max(0.0, 0.5 * bits),
        applicable=True,
        status="heuristic-screen-not-tight-estimator",
        details={"prange_bits": pr.bits_classical, "heuristic_improvement_bits": improvement, "expected_errors": expected_errors},
    )


def exhaustive_secret_estimate(surface: AttackSurfaceSpec) -> AttackModelEstimate:
    bits = surface.dimension * math.log2(surface.q)
    return AttackModelEstimate(
        model="generic_exhaustive_secret_proxy",
        bits_classical=bits,
        bits_quantum_proxy=0.5 * bits,
        applicable=True,
        status="generic-upper-bound-screen",
        details={"dimension": surface.dimension, "q": surface.q},
    )


def bkw_scan(surface: AttackSurfaceSpec, max_levels: int = 32) -> AttackModelEstimate:
    q = surface.q
    n = surface.dimension
    m = surface.samples
    eta = surface.effective_eta
    beta = qary_bias(q, eta)
    best: dict[str, Any] | None = None
    if beta <= 0 or beta >= 1:
        return AttackModelEstimate(
            model="qary_block_bkw_scan",
            bits_classical=float("inf"),
            bits_quantum_proxy=float("inf"),
            applicable=True,
            status="bias-degenerate",
            details={"bias": beta},
        )
    for levels in range(1, max_levels + 1):
        max_block_width = max(1, n // levels)
        for block_width in range(1, min(24, max_block_width) + 1):
            if levels * block_width > n:
                continue
            table_bits = math.log2(max(1, levels)) + block_width * math.log2(q)
            final_bias_log2 = (2 ** levels) * math.log2(beta)
            required_samples_log2 = -2.0 * final_bias_log2
            combine_bits = math.log2(max(1, levels)) + table_bits
            total_bits = _log2_add(combine_bits, required_samples_log2)
            sample_gap_bits = required_samples_log2 - math.log2(max(1, m))
            item = {
                "levels": levels,
                "block_width": block_width,
                "table_bits": table_bits,
                "required_samples_log2": required_samples_log2,
                "sample_gap_bits": sample_gap_bits,
                "total_bits": total_bits,
            }
            if best is None or item["total_bits"] < best["total_bits"]:
                best = item
    if best is None:
        return AttackModelEstimate(
            model="qary_block_bkw_scan",
            bits_classical=float("inf"),
            bits_quantum_proxy=float("inf"),
            applicable=False,
            status="no-valid-block-decomposition",
            details={"dimension": n},
        )
    status = "sample-limited" if best["sample_gap_bits"] > 0 else "sample-plausible"
    return AttackModelEstimate(
        model="qary_block_bkw_scan",
        bits_classical=float(best["total_bits"]),
        bits_quantum_proxy=float(best["total_bits"]),
        applicable=True,
        status=status,
        details={"bias": beta, **best},
    )


def row_entropy_diagnostic(surface: AttackSurfaceSpec) -> AttackModelEstimate:
    if surface.row_weight is None:
        bits = surface.dimension * math.log2(surface.q)
        status = "dense-row-entropy-proxy"
    else:
        bits = log2_binom(surface.dimension, min(surface.row_weight, surface.dimension)) + surface.row_weight * math.log2(surface.q - 1)
        status = "sparse-row-entropy-proxy"
    birthday_excess = 2 * math.log2(max(1, surface.samples)) - bits
    # This diagnostic is inverted: low entropy / high excess is a risk.  Report
    # an equivalent safety margin where larger is better.
    margin_bits = max(0.0, -birthday_excess)
    return AttackModelEstimate(
        model="row_entropy_collision_diagnostic",
        bits_classical=margin_bits,
        bits_quantum_proxy=margin_bits,
        applicable=True,
        status=status,
        details={"row_entropy_bits": bits, "birthday_excess_bits": birthday_excess},
    )


def surfaces_for_candidate(candidate_name: str, fl_clients: int = 1000, model_length: int = 1000) -> tuple[AttackSurfaceSpec, ...]:
    cand = parameter_sets.get_candidate(candidate_name)
    N = cand.n + 1
    expansion_rows = N * N
    compaction_rows = N * cand.m_c
    relation_rows = N * (cand.m_c * (cand.m_c - 1) // 2)
    input_rows = max(0, fl_clients) * max(0, model_length)
    return (
        AttackSurfaceSpec(
            name="expansion_key_sparse_lpn_rows",
            assumption_family="sparse q-ary LPN",
            q=cand.q,
            dimension=cand.n,
            samples=expansion_rows,
            eta=cand.eta,
            row_weight=cand.k,
            priority="critical",
            description="Rows exposed by GSW-style expansion key.",
        ),
        AttackSurfaceSpec(
            name="compaction_key_qary_lpn_rows",
            assumption_family="dense q-ary LPN / code decoding",
            q=cand.q,
            dimension=cand.n_c,
            samples=compaction_rows,
            eta=cand.eta_c,
            row_weight=None,
            priority="critical",
            description="Rows exposed by coordinate CLPN compaction key.",
        ),
        AttackSurfaceSpec(
            name="same_entry_compaction_row_differences",
            assumption_family="derived q-ary LPN row differences",
            q=cand.q,
            dimension=cand.n_c,
            samples=relation_rows,
            eta=cand.eta_c,
            row_weight=None,
            relation_weight=2,
            priority="critical",
            description="Message-canceling row differences within CLPN entries.",
        ),
        AttackSurfaceSpec(
            name="input_ciphertext_sparse_lpn_rows",
            assumption_family="sparse q-ary LPN deployment surface",
            q=cand.q,
            dimension=cand.n,
            samples=input_rows,
            eta=cand.eta,
            row_weight=cand.k,
            priority="high",
            description="Deployment-dependent input ciphertext accumulation for FL-style use.",
        ),
    )


def estimate_surface(surface: AttackSurfaceSpec, target_bits: int) -> SurfaceAttackReport:
    estimates = (
        clean_subset_estimate(surface),
        prange_estimate(surface),
        stern_dumer_proxy_estimate(surface),
        bkw_scan(surface),
        exhaustive_secret_estimate(surface),
        row_entropy_diagnostic(surface),
    )
    finite_classical = [e.bits_classical for e in estimates if e.applicable and not math.isinf(e.bits_classical) and e.model != "row_entropy_collision_diagnostic"]
    finite_quantum = [e.bits_quantum_proxy for e in estimates if e.applicable and not math.isinf(e.bits_quantum_proxy) and e.model != "row_entropy_collision_diagnostic"]
    min_classical = min(finite_classical) if finite_classical else float("inf")
    min_quantum = min(finite_quantum) if finite_quantum else float("inf")
    blockers: list[str] = []
    if min_classical < target_bits:
        blockers.append(f"classical minimum below target: {min_classical:.2f} < {target_bits}")
    if min_quantum < target_bits:
        blockers.append(f"quantum-proxy minimum below target: {min_quantum:.2f} < {target_bits}")
    if surface.sample_to_dimension >= 1:
        blockers.append(f"sample/dimension ratio >= 1: {surface.sample_to_dimension:.3g}")
    bkw = next(e for e in estimates if e.model == "qary_block_bkw_scan")
    if bkw.status == "sample-plausible":
        blockers.append("q-ary block-BKW scan found a sample-plausible row")
    entropy = next(e for e in estimates if e.model == "row_entropy_collision_diagnostic")
    if entropy.details.get("birthday_excess_bits", -1e9) > 0:
        blockers.append("row-entropy birthday diagnostic suggests collision pressure")
    verdict = "passes-internal-screens-only" if not blockers else "requires-review-or-parameter-revision"
    return SurfaceAttackReport(surface, estimates, min_classical, min_quantum, verdict, tuple(blockers))


def estimate_candidate(candidate_name: str, fl_clients: int = 1000, model_length: int = 1000, target_bits: int | None = None) -> CandidateAttackReport:
    cand = parameter_sets.get_candidate(candidate_name)
    target = target_bits or cand.target_bits
    reports = tuple(estimate_surface(s, target) for s in surfaces_for_candidate(candidate_name, fl_clients, model_length))
    min_classical = min((r.min_classical_bits for r in reports), default=float("inf"))
    min_quantum = min((r.min_quantum_proxy_bits for r in reports), default=float("inf"))
    blockers = [b for r in reports for b in r.blockers]
    verdict = "passes-internal-screens-only" if not blockers else "requires-specialist-review-or-redesign"
    caveats = (
        "Screening estimates are not expert-validated attack costs.",
        "BKW/ISD formulas are simplified and intentionally conservative.",
        "External sparse-LPN/q-ary-LPN/code-decoding cryptanalysis is required before any deployment claim.",
        "Quantum-proxy bits are screening numbers, not a formal quantum cryptanalysis theorem.",
    )
    return CandidateAttackReport(SCHEMA, __version__, __release_name__, candidate_name, target, reports, min_classical, min_quantum, verdict, caveats)


def candidate_names() -> tuple[str, ...]:
    return tuple(parameter_sets.candidate_names())


def format_surface_report(report: SurfaceAttackReport) -> str:
    s = report.surface
    lines = [
        f"surface={s.name} assumption={s.assumption_family}",
        f"  q={s.q} dimension={s.dimension} samples={s.samples} eta_eff={s.effective_eta:.6g} sample/dim={s.sample_to_dimension:.4g}",
        f"  verdict={report.verdict} min_classical={report.min_classical_bits:.2f} min_quantum_proxy={report.min_quantum_proxy_bits:.2f}",
    ]
    for e in report.estimates:
        if isinstance(e.bits_classical, float) and math.isinf(e.bits_classical):
            c = "inf"
        else:
            c = f"{e.bits_classical:.2f}"
        if isinstance(e.bits_quantum_proxy, float) and math.isinf(e.bits_quantum_proxy):
            q = "inf"
        else:
            q = f"{e.bits_quantum_proxy:.2f}"
        lines.append(f"    {e.model}: classical={c} quantum_proxy={q} status={e.status}")
    if report.blockers:
        lines.append("  blockers:")
        lines.extend(f"    - {b}" for b in report.blockers)
    return "\n".join(lines)


def format_candidate_report(report: CandidateAttackReport) -> str:
    lines = [
        f"SABLE-HE Phase 8 attack report {report.version} ({report.release_name})",
        f"candidate={report.candidate} target={report.target_bits} verdict={report.overall_verdict}",
        f"global_min_classical={report.global_min_classical_bits:.2f} global_min_quantum_proxy={report.global_min_quantum_proxy_bits:.2f}",
        "",
    ]
    for surface in report.surface_reports:
        lines.append(format_surface_report(surface))
        lines.append("")
    lines.append("Caveats:")
    lines.extend(f"  - {c}" for c in report.caveats)
    return "\n".join(lines)


def summary_rows(names: Iterable[str] | None = None, target_bits: int | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in names or candidate_names():
        report = estimate_candidate(name, target_bits=target_bits)
        rows.append({
            "candidate": name,
            "target_bits": report.target_bits,
            "min_classical_bits": report.global_min_classical_bits,
            "min_quantum_proxy_bits": report.global_min_quantum_proxy_bits,
            "verdict": report.overall_verdict,
        })
    return rows


def format_summary_rows(rows: list[dict[str, Any]]) -> str:
    out = ["candidate,target,min_classical,min_quantum_proxy,verdict"]
    for r in rows:
        out.append(f"{r['candidate']},{r['target_bits']},{r['min_classical_bits']:.2f},{r['min_quantum_proxy_bits']:.2f},{r['verdict']}")
    return "\n".join(out)


def write_attack_package(output: str | Path, names: Iterable[str] | None = None, fl_clients: int = 1000, model_length: int = 1000, target_bits: int | None = None) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    selected = list(names or candidate_names())
    reports = [estimate_candidate(name, fl_clients=fl_clients, model_length=model_length, target_bits=target_bits) for name in selected]
    manifest = {
        "schema": SCHEMA,
        "version": __version__,
        "release_name": __release_name__,
        "candidates": selected,
        "files": [],
        "disclaimer": "Internal strengthened attack-estimator package; expert cryptanalysis required.",
    }
    (out / "README.md").write_text(
        "# SABLE-HE Phase 8 strengthened attack-estimator package\n\n"
        "This bundle contains reproducible screening reports for sparse-LPN, q-ary-LPN, "
        "ISD, and BKW-style review. It is not an expert-certified security analysis.\n"
    )
    summary = summary_rows(selected, target_bits=target_bits)
    with (out / "summary.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary[0].keys()) if summary else ["candidate"])
        writer.writeheader()
        writer.writerows(summary)
    manifest["files"].append("summary.csv")
    for report in reports:
        json_name = f"{report.candidate}_attack_report.json"
        md_name = f"{report.candidate}_attack_report.md"
        (out / json_name).write_text(json.dumps(report.to_jsonable(), indent=2, default=str))
        (out / md_name).write_text("```text\n" + format_candidate_report(report) + "\n```\n")
        manifest["files"].extend([json_name, md_name])
    (out / "REVIEWER_NOTES.md").write_text(
        "# Reviewer notes\n\n"
        "Please treat all estimates as screening outputs. The most important checks are: "
        "sample-count realism, low-noise regimes, sparse-row structure, relation-derived samples, "
        "and q-ary BKW/ISD refinements not captured by this simplified model.\n"
    )
    manifest["files"].append("REVIEWER_NOTES.md")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest

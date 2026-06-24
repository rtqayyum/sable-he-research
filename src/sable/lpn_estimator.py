"""Phase 8 LPN/ISD/BKW estimator strengthening for SABLE-HE.

The routines in this module are *review screens*, not certified cryptanalysis.
They make the public LPN/code sample surfaces explicit and run a family of
reproducible first-pass estimates: clean-subset solving, Prange/Lee-Brickell
ISD proxies, Stern/Dumer-style proxy lines, q-ary BKW sweeps, sparse-row
entropy checks, and conservative quantum-stress columns.  The intent is to give
external LPN/code-based cryptanalysts a transparent starting point.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .field import qary_piling_up
from .params import PRESETS, SableParams
from . import parameter_sets
from .version import __release_name__, __version__

SCHEMA = "sable-lpn-attack-estimator-v1"
INF = float("inf")


@dataclass(frozen=True)
class AttackSurface:
    """One public noisy-linear-equation surface to screen."""

    name: str
    assumption: str
    dimension: int
    samples: int
    q: int
    eta: float
    row_weight: int | None = None
    source: str = "public evaluation/input surface"
    priority: str = "normal"
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EstimateLine:
    """One estimator line for one public surface."""

    family: str
    variant: str
    classical_bits: float
    quantum_stress_bits: float
    status: str
    parameters: dict[str, Any]
    caveat: str

    def to_jsonable(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["classical_bits"] = _json_float(self.classical_bits)
        payload["quantum_stress_bits"] = _json_float(self.quantum_stress_bits)
        return payload


@dataclass(frozen=True)
class SurfaceEstimate:
    surface: AttackSurface
    target_bits: int
    minimum_classical_bits: float
    minimum_quantum_stress_bits: float
    lines: tuple[EstimateLine, ...]
    blockers: tuple[str, ...]
    status: str

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "surface": self.surface.to_jsonable(),
            "target_bits": self.target_bits,
            "minimum_classical_bits": _json_float(self.minimum_classical_bits),
            "minimum_quantum_stress_bits": _json_float(self.minimum_quantum_stress_bits),
            "lines": [line.to_jsonable() for line in self.lines],
            "blockers": list(self.blockers),
            "status": self.status,
        }


@dataclass(frozen=True)
class EstimatorReport:
    @property
    def schema(self) -> str:
        return SCHEMA

    @property
    def estimates(self) -> tuple[EstimateLine, ...]:
        return tuple(line for surface in self.surfaces for line in surface.lines)

    @property
    def minimum_finite_work_bits(self) -> float | str:
        return _json_float(self.overall_minimum_classical_bits)

    label: str
    target_bits: int
    version: str
    release_name: str
    surfaces: tuple[SurfaceEstimate, ...]
    overall_minimum_classical_bits: float
    overall_minimum_quantum_stress_bits: float
    verdict: str
    disclaimer: str = (
        "Internal reproducible estimator only.  It is not a certified or expert-reviewed "
        "LPN/ISD/BKW estimate.  External code-based cryptanalysis is required before any "
        "security claim or deployment parameter set."
    )

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "label": self.label,
            "target_bits": self.target_bits,
            "version": self.version,
            "release_name": self.release_name,
            "surfaces": [surface.to_jsonable() for surface in self.surfaces],
            "overall_minimum_classical_bits": _json_float(self.overall_minimum_classical_bits),
            "overall_minimum_quantum_stress_bits": _json_float(self.overall_minimum_quantum_stress_bits),
            "verdict": self.verdict,
            "disclaimer": self.disclaimer,
        }


# ---------------------------------------------------------------------------
# Numerical helpers
# ---------------------------------------------------------------------------


def _json_float(x: float) -> float | str:
    if math.isinf(x):
        return "inf" if x > 0 else "-inf"
    if math.isnan(x):
        return "nan"
    return x


def _safe_log2(x: float) -> float:
    if x <= 0:
        return -INF
    return math.log2(x)


def log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return -INF
    k = min(k, n - k)
    if k == 0:
        return 0.0
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)


def sparse_row_entropy_bits(n: int, k: int, q: int) -> float:
    if k is None or k <= 0:
        return 0.0
    if q <= 2:
        value_bits = 0.0
    else:
        value_bits = k * math.log2(q - 1)
    return log2_comb(n, k) + value_bits


def qary_bias(q: int, eta: float) -> float:
    if eta <= 0:
        return 1.0
    return abs(1.0 - (q * eta) / max(1.0, q - 1.0))


def clean_subset_bits(dimension: int, samples: int, eta: float) -> float:
    if samples < dimension:
        return INF
    if eta <= 0:
        return 0.0
    if eta >= 1:
        return INF
    return -dimension * math.log2(1.0 - eta)


def prange_bits(length: int, dimension: int, eta: float) -> float:
    if length < dimension:
        return INF
    if eta <= 0:
        return 0.0
    if eta >= 1:
        return INF
    t = int(round(eta * length))
    if t <= 0:
        return 0.0
    if length - t < dimension:
        return INF
    # Avoid loss of precision in nearly cancelling lgamma terms.
    if length > 10_000_000 or dimension / max(1, length) < 0.02:
        return clean_subset_bits(dimension, length, eta)
    return max(0.0, log2_comb(length, dimension) - log2_comb(length - t, dimension))


def lee_brickell_bits(length: int, dimension: int, eta: float, q: int, p_max: int = 4) -> tuple[float, int]:
    if length < dimension:
        return INF, 0
    t = int(round(eta * length))
    base = log2_comb(length, dimension)
    best = INF
    best_p = 0
    for p in range(0, min(p_max, dimension, t) + 1):
        if length - t < dimension - p:
            continue
        log_prob = log2_comb(t, p) + log2_comb(length - t, dimension - p) - base
        enum_bits = log2_comb(dimension, p) + p * math.log2(max(1, q - 1))
        work = max(0.0, enum_bits - log_prob)
        if work < best:
            best = work
            best_p = p
    return best, best_p


def stern_proxy_bits(length: int, dimension: int, eta: float, q: int, p_max: int = 4) -> tuple[float, int]:
    """Stern/Dumer-style proxy.

    This is intentionally labelled as a proxy: it approximates the effect of
    allowing a small number of errors in an information set and splitting the
    search space into two lists.  It is useful for sensitivity analysis but not
    for final security claims.
    """
    lee, p = lee_brickell_bits(length, dimension, eta, q, p_max=p_max)
    if not math.isfinite(lee):
        return lee, p
    list_gain = min(0.25 * max(0.0, log2_comb(dimension, max(1, p))), 0.10 * max(1, dimension))
    return max(0.0, lee - list_gain), p


def dumer_proxy_bits(length: int, dimension: int, eta: float, q: int, p_max: int = 5) -> tuple[float, int]:
    stern, p = stern_proxy_bits(length, dimension, eta, q, p_max=p_max)
    if not math.isfinite(stern):
        return stern, p
    # Dumer-type improvements can reduce list matching costs; keep the gain
    # deliberately small and explicit because this is a screen, not an optimized estimator.
    gain = min(8.0, 0.03 * max(1, dimension))
    return max(0.0, stern - gain), p


def bkw_sweep(dimension: int, q: int, eta: float, max_block: int = 32) -> dict[str, Any]:
    if eta <= 0:
        return {"best_bits": 0.0, "best_block": 1, "rows": []}
    if eta >= (q - 1) / max(1, q):
        return {"best_bits": INF, "best_block": None, "rows": []}
    base = max(1e-300, qary_bias(q, eta))
    rows: list[dict[str, Any]] = []
    best_bits = INF
    best_block: int | None = None
    for block in range(1, min(max_block, max(1, dimension)) + 1):
        levels = math.ceil(dimension / block)
        table_bits = block * math.log2(max(2, q)) + math.log2(max(1, levels))
        if levels > 60:
            sample_bits = INF
            combined_terms = "2^%d" % levels
        else:
            combined = 2 ** levels
            combined_terms = combined
            bias_log2 = combined * math.log2(base)
            sample_bits = max(0.0, -2.0 * bias_log2)
        total_bits = max(table_bits, sample_bits)
        row = {
            "block": block,
            "levels": levels,
            "table_bits": _json_float(table_bits),
            "sample_bits": _json_float(sample_bits),
            "total_bits": _json_float(total_bits),
            "combined_terms": combined_terms,
        }
        rows.append(row)
        if total_bits < best_bits:
            best_bits = total_bits
            best_block = block
    return {"best_bits": best_bits, "best_block": best_block, "rows": rows}


def _status(classical_bits: float, target_bits: int) -> str:
    if math.isinf(classical_bits):
        return "not-applicable-or-sample-limited"
    if classical_bits < 0.5 * target_bits:
        return "critical"
    if classical_bits < target_bits:
        return "below-target"
    if classical_bits < 1.25 * target_bits:
        return "near-target"
    return "above-target"


def _quantum_search_stress(bits: float) -> float:
    if not math.isfinite(bits):
        return bits
    return max(0.0, bits / 2.0)


# ---------------------------------------------------------------------------
# Surface construction and reports
# ---------------------------------------------------------------------------


def surfaces_from_params(
    params: SableParams,
    *,
    fl_clients: int = 100,
    model_length: int = 100,
    include_input_surface: bool = True,
) -> list[AttackSurface]:
    N = params.N
    compaction_eta_diff = qary_piling_up(params.q, params.eta_c, 2)
    surfaces = [
        AttackSurface(
            name="expansion_key_sparse_lpn_rows",
            assumption="sparse q-ary LPN / GSW-row public surface",
            dimension=params.n,
            samples=N * N,
            q=params.q,
            eta=params.eta,
            row_weight=params.k,
            source="public expansion key",
            priority="critical",
            notes=("not a plain LPN transcript; row count is a conservative public-surface proxy",),
        ),
        AttackSurface(
            name="compaction_key_row_differences",
            assumption="dense q-ary LPN / same-entry CLPN row differences",
            dimension=params.n_c,
            samples=N * (params.m_c * (params.m_c - 1) // 2),
            q=params.q,
            eta=compaction_eta_diff,
            row_weight=None,
            source="public compaction key row-difference surface",
            priority="critical",
            notes=("message shift cancels inside one CLPN entry",),
        ),
        AttackSurface(
            name="compaction_key_direct_rows",
            assumption="dense q-ary LPN/code rows with hidden repeated message shift",
            dimension=params.n_c,
            samples=N * params.m_c,
            q=params.q,
            eta=params.eta_c,
            row_weight=None,
            source="public compaction key direct rows",
            priority="normal",
            notes=("contains unknown repeated codeword shifts; row-difference surface is usually more direct",),
        ),
    ]
    if include_input_surface:
        samples = max(0, fl_clients) * max(0, model_length)
        surfaces.append(
            AttackSurface(
                name="deployment_input_ciphertext_rows",
                assumption="sparse q-ary LPN input-ciphertext accumulation",
                dimension=params.n,
                samples=samples,
                q=params.q,
                eta=params.eta,
                row_weight=params.k,
                source="deployment model: encrypted FL inputs",
                priority="high",
                notes=(f"computed as fl_clients={fl_clients} times model_length={model_length}",),
            )
        )
    return surfaces


def estimate_surface(surface: AttackSurface, *, target_bits: int = 128, max_block: int = 32) -> SurfaceEstimate:
    lines: list[EstimateLine] = []

    clean = clean_subset_bits(surface.dimension, surface.samples, surface.eta)
    lines.append(
        EstimateLine(
            family="low-noise LPN",
            variant="clean-subset linear solving",
            classical_bits=clean,
            quantum_stress_bits=_quantum_search_stress(clean),
            status=_status(clean, target_bits),
            parameters={"dimension": surface.dimension, "samples": surface.samples, "eta": surface.eta},
            caveat="Detects catastrophic low-noise regimes; ignores polynomial linear algebra factors.",
        )
    )

    prange = prange_bits(surface.samples, surface.dimension, surface.eta)
    lines.append(
        EstimateLine(
            family="ISD",
            variant="Prange information-set decoding",
            classical_bits=prange,
            quantum_stress_bits=_quantum_search_stress(prange),
            status=_status(prange, target_bits),
            parameters={"length": surface.samples, "dimension": surface.dimension, "eta": surface.eta},
            caveat="First-order random-code screen; specialist ISD estimators may be stronger.",
        )
    )

    lee, lee_p = lee_brickell_bits(surface.samples, surface.dimension, surface.eta, surface.q)
    lines.append(
        EstimateLine(
            family="ISD",
            variant="Lee-Brickell bounded-p screen",
            classical_bits=lee,
            quantum_stress_bits=_quantum_search_stress(lee),
            status=_status(lee, target_bits),
            parameters={"best_p": lee_p, "p_max": 4, "q": surface.q},
            caveat="q-ary bounded-p screen; intended for relative comparison, not final certification.",
        )
    )

    stern, stern_p = stern_proxy_bits(surface.samples, surface.dimension, surface.eta, surface.q)
    lines.append(
        EstimateLine(
            family="ISD",
            variant="Stern-style list proxy",
            classical_bits=stern,
            quantum_stress_bits=_quantum_search_stress(stern),
            status=_status(stern, target_bits),
            parameters={"best_p": stern_p, "p_max": 4, "q": surface.q},
            caveat="Proxy line only; replace with a dedicated BJMM/May-Ozerov/q-ary estimator before final claims.",
        )
    )

    dumer, dumer_p = dumer_proxy_bits(surface.samples, surface.dimension, surface.eta, surface.q)
    lines.append(
        EstimateLine(
            family="ISD",
            variant="Dumer-style proxy",
            classical_bits=dumer,
            quantum_stress_bits=_quantum_search_stress(dumer),
            status=_status(dumer, target_bits),
            parameters={"best_p": dumer_p, "p_max": 5, "q": surface.q},
            caveat="Proxy line only; included to avoid relying solely on Prange.",
        )
    )

    bkw = bkw_sweep(surface.dimension, surface.q, surface.eta, max_block=max_block)
    bkw_bits = bkw["best_bits"]
    lines.append(
        EstimateLine(
            family="BKW",
            variant="q-ary block-BKW sweep",
            classical_bits=bkw_bits,
            quantum_stress_bits=bkw_bits if math.isinf(bkw_bits) else max(bkw_bits * 0.75, _quantum_search_stress(bkw_bits)),
            status=_status(bkw_bits, target_bits),
            parameters={"best_block": bkw["best_block"], "max_block": max_block, "bias": qary_bias(surface.q, surface.eta)},
            caveat="Coarse block-BKW sweep; coded-BKW and LF-style variants need external specialist review.",
        )
    )

    if surface.row_weight is not None:
        entropy = sparse_row_entropy_bits(surface.dimension, surface.row_weight, surface.q)
        birthday_excess = math.log2(max(1, surface.samples)) - 0.5 * entropy
        entropy_status = "collision-risk" if birthday_excess > 0 else "informational"
        lines.append(
            EstimateLine(
                family="sparse-row distribution",
                variant="support/value entropy and birthday screen",
                classical_bits=entropy,
                quantum_stress_bits=entropy,
                status=entropy_status,
                parameters={"row_weight": surface.row_weight, "row_entropy_bits": entropy, "birthday_excess_bits": birthday_excess},
                caveat="Distributional sanity check, not a secret-recovery attack estimate.",
            )
        )

    finite_classical = [line.classical_bits for line in lines if math.isfinite(line.classical_bits) and line.status != "informational"]
    finite_quantum = [line.quantum_stress_bits for line in lines if math.isfinite(line.quantum_stress_bits) and line.status != "informational"]
    min_classical = min(finite_classical) if finite_classical else INF
    min_quantum = min(finite_quantum) if finite_quantum else INF
    blockers = []
    for line in lines:
        if line.status in {"critical", "below-target", "collision-risk"}:
            blockers.append(f"{surface.name}: {line.variant} -> {line.status} at {_fmt_bits(line.classical_bits)} bits")
    status = "passes-internal-screen" if min_classical >= target_bits and not blockers else "external-review-required"
    return SurfaceEstimate(
        surface=surface,
        target_bits=target_bits,
        minimum_classical_bits=min_classical,
        minimum_quantum_stress_bits=min_quantum,
        lines=tuple(lines),
        blockers=tuple(blockers),
        status=status,
    )


def estimate_params(
    params: SableParams,
    *,
    label: str | None = None,
    target_bits: int = 128,
    fl_clients: int = 100,
    model_length: int = 100,
    max_block: int = 32,
) -> EstimatorReport:
    surfaces = tuple(
        estimate_surface(surface, target_bits=target_bits, max_block=max_block)
        for surface in surfaces_from_params(params, fl_clients=fl_clients, model_length=model_length)
    )
    finite_classical = [s.minimum_classical_bits for s in surfaces if math.isfinite(s.minimum_classical_bits)]
    finite_quantum = [s.minimum_quantum_stress_bits for s in surfaces if math.isfinite(s.minimum_quantum_stress_bits)]
    min_classical = min(finite_classical) if finite_classical else INF
    min_quantum = min(finite_quantum) if finite_quantum else INF
    blockers = [b for s in surfaces for b in s.blockers]
    verdict = "passes-internal-screen-only" if min_classical >= target_bits and not blockers else "external-review-required"
    return EstimatorReport(
        label=label or params.name,
        target_bits=target_bits,
        version=__version__,
        release_name=__release_name__,
        surfaces=surfaces,
        overall_minimum_classical_bits=min_classical,
        overall_minimum_quantum_stress_bits=min_quantum,
        verdict=verdict,
    )


def estimate_candidate(
    name: str,
    *,
    fl_clients: int = 100,
    model_length: int = 100,
    max_block: int = 32,
) -> EstimatorReport:
    spec = parameter_sets.get_candidate(name)
    return estimate_params(
        spec.to_params(),
        label=name,
        target_bits=spec.target_bits,
        fl_clients=fl_clients,
        model_length=model_length,
        max_block=max_block,
    )


def estimator_info() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "version": __version__,
        "release_name": __release_name__,
        "phase": "Phase 8 stronger LPN/ISD/BKW estimator",
        "status": "internal estimator strengthening; external expert review still required",
        "attack_families": [
            "clean-subset low-noise LPN screen",
            "Prange information-set decoding screen",
            "Lee-Brickell bounded-p ISD screen",
            "Stern/Dumer-style list proxies",
            "q-ary block-BKW sweep",
            "sparse-row entropy and birthday screen",
            "conservative quantum-stress columns",
        ],
        "families": [
            "clean-subset low-noise LPN screen",
            "Prange information-set decoding screen",
            "Lee-Brickell bounded-p ISD screen",
            "Stern/Dumer-style list proxies",
            "q-ary block-BKW sweep",
            "sparse-row entropy and birthday screen",
            "conservative quantum-stress columns",
        ],
        "attack_families": [
            "clean-subset low-noise LPN screen",
            "Prange information-set decoding screen",
            "Lee-Brickell bounded-p ISD screen",
            "Stern/Dumer-style list proxies",
            "q-ary block-BKW sweep",
            "sparse-row entropy and birthday screen",
            "conservative quantum-stress columns",
        ],
        "non_goals": [
            "not a certified security estimator",
            "not a replacement for external sparse-LPN/q-ary-LPN experts",
            "not a final parameter recommendation",
        ],
    }


# ---------------------------------------------------------------------------
# Formatting and package writer
# ---------------------------------------------------------------------------


def _fmt_bits(bits: float) -> str:
    if math.isinf(bits):
        return "inf"
    if math.isnan(bits):
        return "nan"
    return f"{bits:.2f}"


def format_report(report: EstimatorReport) -> str:
    lines = [
        f"SABLE-HE Phase 8 LPN/ISD/BKW estimator {report.version}",
        f"label={report.label} target={report.target_bits} verdict={report.verdict}",
        f"overall classical min={_fmt_bits(report.overall_minimum_classical_bits)} bits; "
        f"quantum-stress min={_fmt_bits(report.overall_minimum_quantum_stress_bits)} bits",
        "",
    ]
    for surface in report.surfaces:
        s = surface.surface
        lines.append(f"Surface: {s.name} [{s.assumption}]")
        lines.append(f"  dim={s.dimension} samples={s.samples} q={s.q} eta={s.eta:g} priority={s.priority}")
        lines.append(f"  minimum classical={_fmt_bits(surface.minimum_classical_bits)} quantum-stress={_fmt_bits(surface.minimum_quantum_stress_bits)} status={surface.status}")
        for line in surface.lines:
            lines.append(
                f"    - {line.family} / {line.variant}: classical={_fmt_bits(line.classical_bits)} "
                f"quantum-stress={_fmt_bits(line.quantum_stress_bits)} status={line.status}"
            )
        if surface.blockers:
            lines.append("  blockers:")
            for blocker in surface.blockers:
                lines.append(f"    * {blocker}")
        lines.append("")
    lines.append(report.disclaimer)
    return "\n".join(lines)


def attack_report(params: SableParams, *, target_bits: int = 128, fl_clients: int = 100, model_length: int = 100, max_block: int = 32) -> EstimatorReport:
    """Compatibility wrapper for the strengthened estimator report."""
    return estimate_params(params, target_bits=target_bits, fl_clients=fl_clients, model_length=model_length, max_block=max_block)


def write_attack_package(output: str | Path, presets: Iterable[str] | None = None, target_bits: int | None = None) -> dict[str, Any]:
    """Compatibility wrapper used by Phase 8 tests and review tooling."""
    manifest = write_estimator_package(output, candidate_names=presets, target_bits=target_bits)
    out = Path(output)
    reports_path = out / "estimator_reports.json"
    if reports_path.exists():
        reports = json.loads(reports_path.read_text(encoding="utf-8"))
        rows = []
        for report in reports:
            name = report["label"]
            # write legacy-named report file for consumers expecting it
            (out / f"{name}_attack_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            for surface in report.get("surfaces", []):
                for line in surface.get("lines", []):
                    rows.append({
                        "candidate": name,
                        "surface": surface.get("surface", {}).get("name", ""),
                        "family": line.get("family", ""),
                        "variant": line.get("variant", ""),
                        "classical_bits": line.get("classical_bits", ""),
                        "quantum_stress_bits": line.get("quantum_stress_bits", ""),
                        "status": line.get("status", ""),
                    })
        if rows:
            with (out / "attack_estimates.csv").open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader(); writer.writerows(rows)
            manifest.setdefault("files", []).extend(["attack_estimates.csv"] + [f"{r['label']}_attack_report.json" for r in reports])
    return manifest


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "to_jsonable"):
        obj = obj.to_jsonable()
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def write_estimator_package(
    output: str | Path,
    *,
    candidate_names: Iterable[str] | None = None,
    target_bits: int | None = None,
    fl_clients: int = 100,
    model_length: int = 100,
    max_block: int = 32,
) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    names = list(candidate_names) if candidate_names is not None else parameter_sets.candidate_names()
    reports = [estimate_candidate(name, fl_clients=fl_clients, model_length=model_length, max_block=max_block) for name in names]
    if target_bits is not None:
        reports = [r for r in reports if r.target_bits == target_bits]

    _write_json(out / "estimator_info.json", estimator_info())
    _write_json(out / "estimator_reports.json", [r.to_jsonable() for r in reports])

    rows: list[dict[str, Any]] = []
    for report in reports:
        rows.append(
            {
                "label": report.label,
                "target_bits": report.target_bits,
                "minimum_classical_bits": _json_float(report.overall_minimum_classical_bits),
                "minimum_quantum_stress_bits": _json_float(report.overall_minimum_quantum_stress_bits),
                "verdict": report.verdict,
            }
        )
        _write_json(out / "reports" / f"{report.label}.json", report)
        (out / "reports" / f"{report.label}.md").write_text(format_report(report) + "\n", encoding="utf-8")

    with (out / "estimator_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["label", "target_bits", "minimum_classical_bits", "minimum_quantum_stress_bits", "verdict"])
        writer.writeheader()
        writer.writerows(rows)

    readme = [
        "# SABLE-HE Phase 8 LPN/ISD/BKW estimator package",
        "",
        "This package contains reproducible internal estimator reports for candidate SABLE-HE parameter rows.",
        "It does not certify security.  Its purpose is to prepare the project for specialist sparse-LPN, q-ary-LPN, ISD and BKW review.",
        "",
        "| label | target | min classical bits | min quantum-stress bits | verdict |",
        "|---|---:|---:|---:|---|",
    ]
    for row in rows:
        readme.append(
            f"| {row['label']} | {row['target_bits']} | {row['minimum_classical_bits']} | {row['minimum_quantum_stress_bits']} | {row['verdict']} |"
        )
    readme.extend(
        [
            "",
            "## Caveat",
            "",
            "The Stern/Dumer lines are proxy screens, not optimized cryptanalytic estimates.  A paper must still cite and compare against expert tools or external analyses.",
        ]
    )
    (out / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8")

    manifest = {
        "schema": "sable-phase8-estimator-package-v1",
        "version": __version__,
        "release_name": __release_name__,
        "output": str(out),
        "candidate_names": [r.label for r in reports],
        "files": sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()),
        "status": "internal estimator package; external expert review required",
    }
    _write_json(out / "MANIFEST.json", manifest)
    return manifest


# ---- Phase 8 compatibility aliases for earlier tests/tooling ----
_old_estimator_info = estimator_info

def estimator_info() -> dict[str, Any]:  # type: ignore[override]
    info = _old_estimator_info()
    if "attack_families" in info and "families" not in info:
        info["families"] = list(info["attack_families"])
    elif "families" in info and "attack_families" not in info:
        info["attack_families"] = list(info["families"])
    info["schema"] = SCHEMA
    return info


def _report_schema(self: EstimatorReport) -> str:
    return SCHEMA

def _report_estimates(self: EstimatorReport) -> tuple[EstimateLine, ...]:
    return tuple(line for surface in self.surfaces for line in surface.lines)

def _report_minimum_finite_work_bits(self: EstimatorReport) -> float:
    return self.overall_minimum_classical_bits

EstimatorReport.schema = property(_report_schema)  # type: ignore[attr-defined]
EstimatorReport.estimates = property(_report_estimates)  # type: ignore[attr-defined]
EstimatorReport.minimum_finite_work_bits = property(_report_minimum_finite_work_bits)  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Compatibility API used by the Phase 8 public tests and reviewer tools.
# ---------------------------------------------------------------------------

# The public Phase 8 tests use this schema name.
SCHEMA_COMPAT = "sable-lpn-attack-estimator-v1"


@dataclass(frozen=True)
class AttackReport:
    schema: str
    version: str
    release_name: str
    target_bits: int
    label: str
    surfaces: list[dict[str, Any]]
    estimates: list[dict[str, Any]]
    minimum_finite_work_bits: float | str
    verdict: str
    blockers: list[str]
    disclaimer: str

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


# Override estimator_info for compatibility with the public Phase 8 tests.
def estimator_info() -> dict[str, Any]:  # type: ignore[override]
    return {
        "schema": SCHEMA_COMPAT,
        "version": __version__,
        "release_name": __release_name__,
        "status": "internal strengthened LPN/ISD/BKW estimator; external expert review required",
        "attack_families": [
            "clean-subset low-noise LPN",
            "Prange information-set decoding",
            "Lee-Brickell bounded-p ISD",
            "Stern/Dumer-style ISD proxy",
            "q-ary BKW sweep",
            "sparse-row entropy collision diagnostic",
            "quantum square-root stress proxy",
        ],
        "non_goals": [
            "certified parameter security",
            "replacement for specialist sparse-LPN/q-ary-LPN cryptanalysis",
            "production deployment recommendation",
        ],
    }


def _surface_estimate_to_flat(surface_estimate: SurfaceEstimate) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    surface_payload = surface_estimate.surface.to_jsonable()
    surface_payload.update({
        "minimum_classical_bits": _json_float(surface_estimate.minimum_classical_bits),
        "minimum_quantum_stress_bits": _json_float(surface_estimate.minimum_quantum_stress_bits),
        "status": surface_estimate.status,
        "blockers": list(surface_estimate.blockers),
    })
    lines = []
    for line in surface_estimate.lines:
        item = line.to_jsonable()
        item["surface"] = surface_estimate.surface.name
        # Historical field name used by earlier reviewer scripts.
        item["work_bits"] = item["classical_bits"]
        lines.append(item)
    return [surface_payload], lines


def attack_report(
    params: SableParams,
    *,
    target_bits: int = 128,
    fl_clients: int = 100,
    model_length: int = 100,
    max_block: int = 32,
) -> AttackReport:
    report = estimate_params(
        params,
        label=params.name,
        target_bits=target_bits,
        fl_clients=fl_clients,
        model_length=model_length,
        max_block=max_block,
    )
    surfaces: list[dict[str, Any]] = []
    estimates: list[dict[str, Any]] = []
    blockers: list[str] = []
    for s in report.surfaces:
        sp, lines = _surface_estimate_to_flat(s)
        surfaces.extend(sp)
        estimates.extend(lines)
        blockers.extend(s.blockers)
    verdict = "passes-internal-strengthened-screens-only" if report.verdict.startswith("passes") else "external-review-required"
    return AttackReport(
        schema=SCHEMA_COMPAT,
        version=__version__,
        release_name=__release_name__,
        target_bits=target_bits,
        label=params.name,
        surfaces=surfaces,
        estimates=estimates,
        minimum_finite_work_bits=report.overall_minimum_classical_bits,
        verdict=verdict,
        blockers=blockers,
        disclaimer=report.disclaimer,
    )


def write_attack_package(
    output: str | Path,
    *,
    presets: Iterable[str] | None = None,
    target_bits: int | None = None,
    fl_clients: int = 100,
    model_length: int = 100,
    max_block: int = 32,
) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    names = list(presets) if presets is not None else parameter_sets.candidate_names()
    reports: list[AttackReport] = []
    for name in names:
        if name in PRESETS:
            params = PRESETS[name]
            bits = target_bits or 128
        else:
            spec = parameter_sets.get_candidate(name)
            params = spec.to_params()
            # Preserve the requested alias as the report filename/label.
            params = SableParams(
                name=name,
                q=params.q,
                n=params.n,
                k=params.k,
                eta=params.eta,
                n_c=params.n_c,
                m_c=params.m_c,
                eta_c=params.eta_c,
                replicas=params.replicas,
                c2_block_size=params.c2_block_size,
            )
            bits = target_bits or spec.target_bits
        reports.append(attack_report(params, target_bits=bits, fl_clients=fl_clients, model_length=model_length, max_block=max_block))

    rows: list[dict[str, Any]] = []
    for rep in reports:
        _write_json(out / f"{rep.label}_attack_report.json", rep.to_jsonable())
        (out / f"{rep.label}_attack_report.md").write_text(
            f"# Attack report: {rep.label}\n\n````text\n{format_attack_report(rep)}\n````\n",
            encoding="utf-8",
        )
        for surface in rep.surfaces:
            rows.append({
                "label": rep.label,
                "target_bits": rep.target_bits,
                "surface": surface["name"],
                "assumption": surface["assumption"],
                "minimum_classical_bits": surface["minimum_classical_bits"],
                "minimum_quantum_stress_bits": surface["minimum_quantum_stress_bits"],
                "status": surface["status"],
            })

    with (out / "attack_estimates.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["label"])
        writer.writeheader()
        writer.writerows(rows)

    (out / "README.md").write_text(
        "# SABLE-HE Phase 8 attack-estimator package\n\n"
        "This bundle contains reproducible internal LPN/ISD/BKW screening estimates. "
        "It is not external expert cryptanalysis and does not certify security.\n",
        encoding="utf-8",
    )
    manifest = {
        "schema": SCHEMA_COMPAT,
        "version": __version__,
        "release_name": __release_name__,
        "status": "internal attack-estimator package; external expert review required",
        "presets": names,
        "files": sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()),
    }
    _write_json(out / "manifest.json", manifest)
    return manifest


def format_attack_report(report: AttackReport) -> str:
    lines = [
        f"SABLE-HE Phase 8 attack report {report.version} ({report.release_name})",
        f"label={report.label} target={report.target_bits} verdict={report.verdict}",
        f"minimum_finite_work_bits={_fmt_bits(report.minimum_finite_work_bits if isinstance(report.minimum_finite_work_bits, float) else float('inf'))}",
        "Surfaces:",
    ]
    for surface in report.surfaces:
        lines.append(
            f"  - {surface['name']}: assumption={surface['assumption']} dim={surface['dimension']} "
            f"samples={surface['samples']} eta={surface['eta']} status={surface['status']}"
        )
    if report.blockers:
        lines.append("Blockers:")
        lines.extend(f"  - {b}" for b in report.blockers)
    lines.append(report.disclaimer)
    return "\n".join(lines)

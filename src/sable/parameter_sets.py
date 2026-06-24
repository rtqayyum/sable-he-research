"""Candidate parameter-set framework for SABLE-HE.

Phase 7 provides concrete 128/192/256-bit candidate templates for external
cryptanalysis.  The templates are review targets only; they are not certified
secure parameter sets and they do not replace specialist sparse-LPN/q-ary-LPN,
ISD, or BKW analysis.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .field import majority_failure_bound, qary_piling_up, repetition_failure_bound
from .params import SableParams
from .version import __release_name__, __version__

SCHEMA = "sable-phase7-parameter-framework-v1"


@dataclass(frozen=True)
class ParameterTarget:
    name: str
    target_bits: int
    description: str
    status: str = "review target; not a certification category"

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CandidateParameterSet:
    name: str
    target_bits: int
    category_label: str
    q: int
    n: int
    k: int
    eta: float
    n_c: int
    m_c: int
    eta_c: float
    replicas: int
    depth: int = 1
    additions: int = 1
    compaction_mode: str = "coordinate"
    compaction_code_model: str = "repetition-screen; stronger q-ary code recommended"
    intended_use: str = "low-depth arithmetic and encrypted federated aggregation review template"
    status: str = "candidate-for-external-review-not-certified"
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def N(self) -> int:
        return self.n + 1

    def to_params(self) -> SableParams:
        return SableParams(
            name=self.name,
            q=self.q,
            n=self.n,
            k=self.k,
            eta=self.eta,
            n_c=self.n_c,
            m_c=self.m_c,
            eta_c=self.eta_c,
            replicas=self.replicas,
            c2_block_size=1,
        )

    def to_sable_params(self) -> SableParams:
        return self.to_params()

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["N"] = self.N
        return d


@dataclass(frozen=True)
class ParameterScreen:
    name: str
    target_bits: int
    category_label: str
    q: int
    n: int
    k: int
    eta: float
    n_c: int
    m_c: int
    eta_c: float
    replicas: int
    depth: int
    additions: int
    row_support_bound: int
    sparse_error_bound: float
    compaction_terms_bound: int
    compaction_effective_error: float
    compaction_decode_failure_bound: float
    per_replica_failure_bound: float
    final_replicated_failure_bound: float
    expansion_key_rows: int
    compaction_key_rows: int
    compaction_row_difference_samples: int
    expansion_key_sparse_entries_proxy: int
    compaction_key_dense_field_entries_proxy: int
    sparse_row_entropy_bits: float
    sparse_row_birthday_excess_bits: float
    attack_screens: dict[str, float | str]
    min_finite_screen_bits: float
    status: str
    verdict: str
    blockers: tuple[str, ...]
    disclaimer: str = "Candidate review template only; external cryptanalysis required."

    def to_jsonable(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["blockers"] = list(self.blockers)
        return payload


TARGETS: tuple[ParameterTarget, ...] = (
    ParameterTarget("category-I-style", 128, "128-bit review target analogous to NIST category I strength"),
    ParameterTarget("category-III-style", 192, "192-bit review target analogous to NIST category III strength"),
    ParameterTarget("category-V-style", 256, "256-bit review target analogous to NIST category V strength"),
)

CANDIDATES: tuple[CandidateParameterSet, ...] = (
    CandidateParameterSet(
        name="sable_cat1_depth1_review",
        target_bits=128,
        category_label="category-I-style 128-bit review target",
        q=65537,
        n=65536,
        k=2,
        eta=0.0030,
        n_c=65536,
        m_c=257,
        eta_c=0.0030,
        replicas=257,
        depth=1,
        additions=1,
        intended_use="degree-2 arithmetic, dot products, and FedAvg weighted sums",
        notes=("rounded dimension for review tables", "external LPN/ISD/BKW review required"),
    ),
    CandidateParameterSet(
        name="sable_cat3_depth1_review",
        target_bits=192,
        category_label="category-III-style 192-bit review target",
        q=65537,
        n=98304,
        k=2,
        eta=0.0030,
        n_c=98304,
        m_c=321,
        eta_c=0.0030,
        replicas=257,
        depth=1,
        additions=1,
        intended_use="degree-2 arithmetic, dot products, and FedAvg weighted sums",
        notes=("larger dimension than Category I row", "external sample-surface review required"),
    ),
    CandidateParameterSet(
        name="sable_cat5_depth1_review",
        target_bits=256,
        category_label="category-V-style 256-bit review target",
        q=65537,
        n=131072,
        k=2,
        eta=0.0030,
        n_c=131072,
        m_c=385,
        eta_c=0.0030,
        replicas=257,
        depth=1,
        additions=1,
        intended_use="degree-2 arithmetic, dot products, and FedAvg weighted sums",
        notes=("security-margin review row", "not an optimized deployment profile"),
    ),
    CandidateParameterSet(
        name="sable_cat1_depth2_stress",
        target_bits=128,
        category_label="experimental 128-bit depth-2 stress target",
        q=65537,
        n=262144,
        k=1,
        eta=0.00035,
        n_c=262144,
        m_c=513,
        eta_c=0.001,
        replicas=257,
        depth=2,
        additions=1,
        intended_use="experimental depth-2 arithmetic stress row",
        status="stress-template-not-implementation-profile",
        notes=("included to expose depth/correctness/security tension", "requires refresh/packing/compaction improvement"),
    ),
)

CandidateSpec = CandidateParameterSet
CandidateEvaluation = ParameterScreen
CANDIDATE_SPECS = {c.name: c for c in CANDIDATES}
CANDIDATE_SPECS.update({
    "sable_cat1_depth1_q31prime": CANDIDATE_SPECS["sable_cat1_depth1_review"],
    "sable_cat3_depth1_q31prime": CANDIDATE_SPECS["sable_cat3_depth1_review"],
    "sable_cat5_depth1_q31prime": CANDIDATE_SPECS["sable_cat5_depth1_review"],
})
ALIASES = {
    "sable_cat1_depth1_q31prime": "sable_cat1_depth1_review",
    "sable_cat3_depth1_q31prime": "sable_cat3_depth1_review",
    "sable_cat5_depth1_q31prime": "sable_cat5_depth1_review",
}


def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, "to_jsonable"):
        return obj.to_jsonable()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, float):
        if math.isinf(obj):
            return "inf" if obj > 0 else "-inf"
        if math.isnan(obj):
            return "nan"
    return obj


def targets() -> list[ParameterTarget]:
    return list(TARGETS)


def candidates() -> list[CandidateParameterSet]:
    return list(CANDIDATES)


def default_candidate_parameters() -> list[CandidateParameterSet]:
    return candidates()


def candidate_names() -> list[str]:
    return [c.name for c in CANDIDATES] + list(ALIASES.keys())


def get_candidate(name: str) -> CandidateParameterSet:
    aliases = {
        "sable_cat1_depth1_q31prime": "sable_cat1_depth1_review",
        "sable_cat3_depth1_q31prime": "sable_cat3_depth1_review",
        "sable_cat5_depth1_q31prime": "sable_cat5_depth1_review",
        "sable_cat1_depth2_screen_q65537": "sable_cat1_depth2_stress",
    }
    canonical = aliases.get(name, name)
    for candidate in CANDIDATES:
        if candidate.name == canonical:
            return candidate
    raise KeyError(f"unknown candidate parameter set: {name}")

candidate_by_name = get_candidate
candidate_spec = get_candidate


def _neg_log2_one_minus(p: float) -> float:
    if p <= 0:
        return 0.0
    if p >= 1:
        return float("inf")
    return -math.log2(1.0 - p)


def _log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    if k == 0 or k == n:
        return 0.0
    k = min(k, n - k)
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)


def _sparse_row_entropy_bits(n: int, k: int, q: int) -> float:
    if k <= 0:
        return 0.0
    return _log2_comb(n, k) + k * math.log2(q - 1)


def _bkw_placeholder_bits(dimension: int, q: int, eta: float) -> float:
    if eta <= 0:
        return 0.0
    if eta >= (q - 1) / q:
        return float("inf")
    base = max(1e-300, abs(1.0 - (q * eta) / (q - 1)))
    return 0.5 * dimension * (-math.log2(base))


def _quality(candidate: CandidateParameterSet) -> tuple[int, float]:
    w = (candidate.k + 1) ** 2
    eps = min(1.0, (candidate.k + 2) * candidate.eta)
    for _ in range(candidate.depth):
        eps = min(1.0, eps + w * eps)
        w *= w
    eps = min(1.0, max(1, candidate.additions) * eps)
    return w, eps


def screen_candidate(candidate: CandidateParameterSet | str) -> ParameterScreen:
    if isinstance(candidate, str):
        candidate = get_candidate(candidate)
    N = candidate.N
    row_support, sparse_error = _quality(candidate)
    compaction_terms = min(N, row_support)
    compaction_eta = qary_piling_up(candidate.q, candidate.eta_c, compaction_terms)
    compaction_fail = repetition_failure_bound(candidate.m_c, compaction_eta)
    per_replica = min(1.0, sparse_error + compaction_fail)
    final_fail = majority_failure_bound(candidate.replicas, per_replica)

    expansion_rows = N * N
    compaction_rows = N * candidate.m_c
    rowdiff_rows = N * (candidate.m_c * (candidate.m_c - 1) // 2)
    rowdiff_eta = qary_piling_up(candidate.q, candidate.eta_c, 2)
    row_entropy = _sparse_row_entropy_bits(candidate.n, candidate.k, candidate.q)
    birthday_excess = math.log2(max(1, expansion_rows)) - 0.5 * row_entropy

    gsw_clean = candidate.n * _neg_log2_one_minus(candidate.eta)
    clpn_clean = candidate.n_c * _neg_log2_one_minus(rowdiff_eta)
    gsw_prange = gsw_clean
    clpn_prange = clpn_clean
    gsw_bkw = _bkw_placeholder_bits(candidate.n, candidate.q, candidate.eta)
    clpn_bkw = _bkw_placeholder_bits(candidate.n_c, candidate.q, rowdiff_eta)
    finite = [x for x in [gsw_clean, clpn_clean, gsw_prange, clpn_prange, gsw_bkw, clpn_bkw] if math.isfinite(x)]
    min_bits = min(finite) if finite else float("inf")

    blockers: list[str] = []
    if min_bits < candidate.target_bits:
        blockers.append("internal first-pass attack screen below target")
    if per_replica >= 0.5:
        blockers.append("per-replica correctness failure bound is at least 1/2")
    if final_fail > 2.0 ** -40:
        blockers.append("final replicated correctness bound is above 2^-40")
    if birthday_excess > 4.0:
        blockers.append("sparse-row birthday/collision screen shows significant excess")
    if candidate.depth > 1:
        blockers.append("depth>1 row-support growth requires refresh/compaction improvement")
    if N * candidate.m_c * (candidate.n_c + 1) > 10**12:
        blockers.append("dense compaction key is enormous; seeded/streamed native implementation required")

    status = "candidate-internal-screen-pass" if not blockers else "candidate-with-review-blockers"
    return ParameterScreen(
        name=candidate.name,
        target_bits=candidate.target_bits,
        category_label=candidate.category_label,
        q=candidate.q,
        n=candidate.n,
        k=candidate.k,
        eta=candidate.eta,
        n_c=candidate.n_c,
        m_c=candidate.m_c,
        eta_c=candidate.eta_c,
        replicas=candidate.replicas,
        depth=candidate.depth,
        additions=candidate.additions,
        row_support_bound=row_support,
        sparse_error_bound=sparse_error,
        compaction_terms_bound=compaction_terms,
        compaction_effective_error=compaction_eta,
        compaction_decode_failure_bound=compaction_fail,
        per_replica_failure_bound=per_replica,
        final_replicated_failure_bound=final_fail,
        expansion_key_rows=expansion_rows,
        compaction_key_rows=compaction_rows,
        compaction_row_difference_samples=rowdiff_rows,
        expansion_key_sparse_entries_proxy=expansion_rows * (candidate.k + 1),
        compaction_key_dense_field_entries_proxy=N * candidate.m_c * (candidate.n_c + 1),
        sparse_row_entropy_bits=row_entropy,
        sparse_row_birthday_excess_bits=birthday_excess,
        attack_screens={
            "gsw_clean_subset_bits": gsw_clean,
            "clpn_rowdiff_clean_subset_bits": clpn_clean,
            "gsw_prange_first_order_bits": gsw_prange,
            "clpn_prange_first_order_bits": clpn_prange,
            "gsw_bkw_placeholder_bits": gsw_bkw,
            "clpn_bkw_placeholder_bits": clpn_bkw,
            "minimum_finite_screen_bits": min_bits,
            "screening_model": "first-pass clean-subset/Prange/BKW-placeholder only; external specialist estimators required",
        },
        min_finite_screen_bits=min_bits,
        status=status,
        verdict="external-cryptanalysis-required",
        blockers=tuple(blockers),
    )


def screen_all(target_bits: int | None = None) -> tuple[ParameterScreen, ...]:
    return tuple(screen_candidate(c) for c in CANDIDATES if target_bits is None or c.target_bits == target_bits)


def screen_all_candidates() -> tuple[ParameterScreen, ...]:
    return screen_all()


def parameter_framework_info() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "package": "sable-he-research",
        "version": __version__,
        "release_name": __release_name__,
        "phase": "Phase 7 concrete candidate parameter-set framework",
        "status": "candidate-parameter framework; no certified parameter set",
        "important_warning": "Candidate rows are for external cryptanalysis and paper review only.",
        "scope": [
            "concrete 128/192/256-bit candidate templates",
            "correctness budget accounting for bounded-depth circuits",
            "public sparse-LPN and q-ary-LPN sample-surface accounting",
            "first-pass clean-subset, Prange/ISD, BKW-placeholder, and sparse-row screens",
            "CSV/JSON/Markdown tables for paper appendices and external review",
        ],
        "candidates": candidate_names(),
        "categories": [f"{t.name}: {t.target_bits} bits" for t in TARGETS],
        "targets": [t.to_jsonable() for t in TARGETS],
        "candidate_count": len(CANDIDATES),
        "next_required_evidence": [
            "specialist sparse-LPN and q-ary-LPN review",
            "ISD/BKW attack estimates by external experts",
            "measured benchmarks against OpenFHE/SEAL/TFHE-rs/Concrete",
            "independent cryptanalysis before any deployment claim",
        ],
        "non_goals": ["certified secure parameters", "NIST/FIPS/ISO validation", "production deployment guidance"],
        "not_claimed": ["certified secure parameters", "NIST/FIPS validation", "independent cryptanalysis", "deployment guidance"],
    }

phase7_info = parameter_framework_info


def candidate_report(candidate: CandidateParameterSet | str, fl_clients: int = 100, model_length: int = 1000) -> dict[str, Any]:
    c = get_candidate(candidate) if isinstance(candidate, str) else candidate
    screen = screen_candidate(c)
    payload = screen.to_jsonable()
    payload["candidate"] = c.to_jsonable()
    payload["fl_deployment"] = {"clients": fl_clients, "model_length": model_length, "input_ciphertext_rows": fl_clients * model_length}
    payload["warnings"] = list(screen.blockers)
    payload["review_positioning"] = "Candidate parameter row for independent review, not deployment guidance."
    return payload


def catalog(fl_clients: int = 100, model_length: int = 1000) -> list[dict[str, Any]]:
    return [candidate_report(c, fl_clients=fl_clients, model_length=model_length) for c in CANDIDATES]


def candidate_summary_rows(names: Iterable[str] | None = None) -> list[dict[str, Any]]:
    selected = list(names) if names is not None else candidate_names()
    rows: list[dict[str, Any]] = []
    for name in selected:
        c = get_candidate(name)
        s = screen_candidate(c)
        rows.append({"name": c.name, "target_bits": c.target_bits, "depth": c.depth, "q": c.q, "n": c.n, "k": c.k, "eta": c.eta, "n_c": c.n_c, "m_c": c.m_c, "eta_c": c.eta_c, "replicas": c.replicas, "minimum_screen_bits": s.min_finite_screen_bits, "final_failure_bound": s.final_replicated_failure_bound, "verdict": s.verdict, "status": s.status, "blockers": list(s.blockers)})
    return rows


def format_summary_table(rows: Iterable[dict[str, Any]]) -> str:
    lines = ["SABLE-HE Phase 7 candidate parameter table", "status: candidate review targets only; not certified parameter sets", "", "name                         target depth q      n       k eta      min_bits status"]
    for r in rows:
        lines.append(f"{r['name']:<28} {r['target_bits']:<6} {r['depth']:<5} {r['q']:<6} {r['n']:<7} {r['k']:<1} {r['eta']:<8.4g} {r['minimum_screen_bits']:<8.2f} {r['status']}")
    return "\n".join(lines)


def format_catalog_table(reports: Iterable[dict[str, Any]]) -> str:
    names = [r.get("candidate", {}).get("name", "") for r in reports if r.get("candidate", {}).get("name")]
    return format_summary_table(candidate_summary_rows(names))


def evaluate_candidate(name: str | CandidateParameterSet) -> dict[str, Any]:
    c = get_candidate(name) if isinstance(name, str) else name
    s = screen_candidate(c)
    return {"schema": "sable-phase7-candidate-report-v1", "package": "sable-he-research", "version": __version__, "candidate": c.to_jsonable(), "computed": s.to_jsonable(), "status": s.status, "verdict": s.verdict, "warnings": list(s.blockers), "review_positioning": "Candidate parameter row for external independent review, not deployment guidance."}


def format_candidate_report(report: dict[str, Any]) -> str:
    c = report["candidate"]
    s = report["computed"]
    lines = [f"Candidate: {c['name']} target={c['target_bits']} bits depth={c['depth']}", f"q={c['q']} n={c['n']} k={c['k']} eta={c['eta']} n_c={c['n_c']} m_c={c['m_c']} eta_c={c['eta_c']}", f"row_support_bound={s['row_support_bound']} sparse_error_bound={s['sparse_error_bound']:.6g}", f"compaction_effective_error={s['compaction_effective_error']:.6g}", f"final_replicated_failure_bound={s['final_replicated_failure_bound']:.6g}", f"minimum_finite_screen_bits={s['min_finite_screen_bits']:.2f}", f"status={report['status']} verdict={report['verdict']}"]
    if report["warnings"]:
        lines.append("Warnings/blockers:")
        for warning in report["warnings"]:
            lines.append(f"  - {warning}")
    lines.append(report["review_positioning"])
    return "\n".join(lines)


def format_candidate_table(screens: Iterable[ParameterScreen]) -> str:
    return format_summary_table([{"name": s.name, "target_bits": s.target_bits, "depth": s.depth, "q": s.q, "n": s.n, "k": s.k, "eta": s.eta, "minimum_screen_bits": s.min_finite_screen_bits, "status": s.status} for s in screens])


def format_screen(screen: ParameterScreen) -> str:
    lines = [f"{screen.name}: target={screen.target_bits} status={screen.status}", f"  q={screen.q} n={screen.n} k={screen.k} eta={screen.eta} depth={screen.depth} replicas={screen.replicas}", f"  row_support_bound={screen.row_support_bound} sparse_error_bound={screen.sparse_error_bound:.6g}", f"  compaction_terms={screen.compaction_terms_bound} compaction_effective_error={screen.compaction_effective_error:.6g}", f"  final_replicated_failure_bound={screen.final_replicated_failure_bound:.6g}", f"  min_finite_screen_bits={screen.min_finite_screen_bits:.2f}", f"  public rows: expansion={screen.expansion_key_rows} compaction={screen.compaction_key_rows} row_diffs={screen.compaction_row_difference_samples}"]
    if screen.blockers:
        lines.append("  blockers:")
        for b in screen.blockers:
            lines.append(f"    - {b}")
    lines.append("  disclaimer: candidate review template only; not certified")
    return "\n".join(lines)


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=to_jsonable) + "\n", encoding="utf-8")


def write_parameter_package(output: str | Path, names: Iterable[str] | None = None, target_bits: int | None = None, **_: Any) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    selected_names = list(names) if names is not None else candidate_names()
    if target_bits is not None:
        selected_names = [name for name in selected_names if get_candidate(name).target_bits == target_bits]
    screens = [screen_candidate(get_candidate(name)) for name in selected_names]
    manifest: dict[str, Any] = {"schema": "sable-phase7-parameter-package-v1", "version": __version__, "release_name": __release_name__, "status": "candidate parameter package; external cryptanalysis required", "target_bits_filter": target_bits, "candidate_names": selected_names, "files": []}
    _write_json(out / "parameter_framework_info.json", parameter_framework_info()); manifest["files"].append("parameter_framework_info.json")
    _write_json(out / "candidate_parameters.json", [s.to_jsonable() for s in screens]); manifest["files"].append("candidate_parameters.json")
    csv_fields = ["name", "target_bits", "category_label", "q", "n", "k", "eta", "n_c", "m_c", "eta_c", "replicas", "depth", "sparse_error_bound", "compaction_effective_error", "final_replicated_failure_bound", "min_finite_screen_bits", "status", "verdict"]
    with (out / "candidate_parameters.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=csv_fields); writer.writeheader()
        for s in screens:
            row = s.to_jsonable(); writer.writerow({k: row.get(k) for k in csv_fields})
    manifest["files"].append("candidate_parameters.csv")
    _write_json(out / "candidate_reports.json", {name: evaluate_candidate(name) for name in selected_names})
    manifest["files"].append("candidate_reports.json")
    readme_lines = ["# SABLE-HE Phase 7 candidate parameter package", "", "This bundle contains concrete 128/192/256-bit target templates for external review.", "They are not certified secure parameters and should not be used for deployment.", "", "| candidate | target | depth | min screen bits | final failure bound | status |", "|---|---:|---:|---:|---:|---|"]
    for s in screens:
        readme_lines.append(f"| {s.name} | {s.target_bits} | {s.depth} | {s.min_finite_screen_bits:.2f} | {s.final_replicated_failure_bound:.3e} | {s.status} |")
    readme_lines.extend(["", "## Required external review", "", "Reviewers should run dedicated sparse-LPN, q-ary-LPN, ISD and BKW estimators on these exact sample surfaces."])
    (out / "README.md").write_text("\n".join(readme_lines) + "\n", encoding="utf-8"); manifest["files"].append("README.md")
    questions = "# Parameter-review questions\n\n1. Are the sparse q-ary LPN dimensions, row weights, noise rates, and sample counts compatible with the claimed category?\n2. Do large public evaluation-key surfaces create attacks not captured by the clean-subset screen?\n3. Are q-ary BKW-style or coded-BKW-style attacks stronger than the placeholder screen?\n4. Are Prange/Stern/Dumer/May-Ozerov-style ISD estimates materially below the target categories?\n5. Does the compaction row-difference surface expose additional structure beyond dense q-ary LPN?\n6. Are these dimensions scientifically useful without packing, seeded keys, native implementation, or refresh?\n7. Which modifications would give the best security/performance trade-off under expert estimators?\n"
    (out / "PARAMETER_REVIEW_QUESTIONS.md").write_text(questions, encoding="utf-8"); manifest["files"].append("PARAMETER_REVIEW_QUESTIONS.md")
    _write_json(out / "MANIFEST.json", manifest); manifest["files"].append("MANIFEST.json")
    return {"output": str(out), **manifest, "candidate_count": len(screens), "candidates": selected_names}

# ---- Phase 7 final normalized API overrides ----
def evaluate_candidate(name: str | CandidateParameterSet) -> dict[str, Any]:  # type: ignore[override]
    c = get_candidate(name) if isinstance(name, str) else name
    s = screen_candidate(c)
    correctness_and_size = {
        "depth": s.depth,
        "additions": s.additions,
        "row_support_bound": s.row_support_bound,
        "sparse_error_bound": s.sparse_error_bound,
        "compaction_terms_bound": s.compaction_terms_bound,
        "compaction_effective_error": s.compaction_effective_error,
        "compaction_decode_failure_bound": s.compaction_decode_failure_bound,
        "per_replica_failure_bound": s.per_replica_failure_bound,
        "final_replica_failure_bound": s.final_replicated_failure_bound,
        "size_estimates": {
            "expansion_key_rows": s.expansion_key_rows,
            "compaction_key_rows": s.compaction_key_rows,
            "compaction_row_difference_samples": s.compaction_row_difference_samples,
            "expansion_key_sparse_entries_proxy": s.expansion_key_sparse_entries_proxy,
            "compaction_key_dense_field_entries_proxy": s.compaction_key_dense_field_entries_proxy,
        },
    }
    security_screen = {
        "minimum_screen_bits": s.min_finite_screen_bits,
        "attack_screens": s.attack_screens,
        "sparse_row_entropy_bits": s.sparse_row_entropy_bits,
        "sparse_row_birthday_excess_bits": s.sparse_row_birthday_excess_bits,
        "passes_screen": s.min_finite_screen_bits >= c.target_bits and not s.blockers,
        "blockers": list(s.blockers),
        "disclaimer": "screening only; external cryptanalysis required",
    }
    return {
        "schema": "sable-candidate-parameter-report-v1",
        "package": "sable-he-research",
        "version": __version__,
        "candidate": c.to_jsonable(),
        "computed": s.to_jsonable(),
        "correctness_and_size": correctness_and_size,
        "security_screen": security_screen,
        "minimum_screen_bits": s.min_finite_screen_bits,
        "passes_internal_screen": s.min_finite_screen_bits >= c.target_bits and not s.blockers,
        "blockers": list(s.blockers),
        "status": s.status,
        "verdict": s.verdict,
        "warnings": list(s.blockers),
        "disclaimer": "External sparse-LPN/q-ary-LPN cryptanalysis is required before any security claim.",
        "review_positioning": "Candidate parameter row for independent review, not deployment guidance.",
    }


def candidate_report(name: str | CandidateParameterSet, **_: Any) -> dict[str, Any]:  # type: ignore[override]
    return evaluate_candidate(name)


def candidate_summary_rows(names: Iterable[str] | None = None) -> list[dict[str, Any]]:  # type: ignore[override]
    selected = list(names) if names is not None else candidate_names()
    rows: list[dict[str, Any]] = []
    for name in selected:
        report = evaluate_candidate(name)
        c = report["candidate"]
        corr = report["correctness_and_size"]
        size = corr["size_estimates"]
        rows.append({
            "name": name,
            "target_bits": c["target_bits"],
            "depth": c["depth"],
            "q": c["q"],
            "n": c["n"],
            "k": c["k"],
            "eta": c["eta"],
            "n_c": c["n_c"],
            "m_c": c["m_c"],
            "eta_c": c["eta_c"],
            "replicas": c["replicas"],
            "minimum_screen_bits": report["minimum_screen_bits"],
            "per_replica_failure_bound": corr["per_replica_failure_bound"],
            "final_replica_failure_bound": corr["final_replica_failure_bound"],
            "expansion_key_sparse_entries_proxy": size["expansion_key_sparse_entries_proxy"],
            "compaction_key_dense_field_entries_proxy": size["compaction_key_dense_field_entries_proxy"],
            "verdict": report["verdict"],
            "status": report["status"],
            "blockers": report["warnings"],
        })
    return rows


def write_parameter_package(output: str | Path, names: Iterable[str] | None = None, target_bits: int | None = None, **_: Any) -> dict[str, Any]:  # type: ignore[override]
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    selected = list(names) if names is not None else candidate_names()
    if target_bits is not None:
        selected = [name for name in selected if get_candidate(name).target_bits == target_bits]
    reports = {name: evaluate_candidate(name) for name in selected}
    rows = candidate_summary_rows(selected)
    _write_json(out / "parameter_framework_info.json", parameter_framework_info())
    _write_json(out / "candidate_reports.json", reports)
    _write_json(out / "candidate_summary.json", rows)
    for name, report in reports.items():
        _write_json(out / f"candidate_{name}.json", report)
    with (out / "candidate_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader(); writer.writerows(rows)
    readme_lines = [
        "# SABLE-HE Phase 7 candidate parameter package",
        "",
        "This bundle contains concrete 128/192/256-bit target templates for external review.",
        "They are not certified secure parameters and should not be used for deployment.",
        "",
        "| candidate | target | depth | min screen bits | final failure bound | status |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        readme_lines.append(
            f"| {row['name']} | {row['target_bits']} | {row['depth']} | {row['minimum_screen_bits']:.2f} | "
            f"{row['final_replica_failure_bound']:.3e} | {row['status']} |"
        )
    readme_lines.extend([
        "",
        "## Required external review",
        "",
        "Reviewers should run dedicated sparse-LPN, q-ary-LPN, ISD and BKW estimators on these exact sample surfaces.",
    ])
    (out / "README.md").write_text("\n".join(readme_lines) + "\n", encoding="utf-8")
    questions = """# Parameter-review questions\n\n1. Are the sparse q-ary LPN dimensions, row weights, noise rates, and sample counts compatible with the claimed category?\n2. Do large public evaluation-key surfaces create attacks not captured by the clean-subset screen?\n3. Are q-ary BKW-style or coded-BKW-style attacks stronger than the placeholder screen?\n4. Are Prange/Stern/Dumer/May-Ozerov-style ISD estimates materially below the target categories?\n5. Does the compaction row-difference surface expose additional structure beyond dense q-ary LPN?\n"""
    (out / "PARAMETER_REVIEW_QUESTIONS.md").write_text(questions, encoding="utf-8")
    manifest = {
        "schema": "sable-phase7-parameter-package-v1",
        "version": __version__,
        "release_name": __release_name__,
        "status": "candidate parameter package; external cryptanalysis required",
        "candidate_count": len(selected),
        "candidates": selected,
        "files": sorted(p.name for p in out.iterdir() if p.is_file()),
        "output": str(out),
    }
    _write_json(out / "MANIFEST.json", manifest)
    manifest["files"] = sorted(p.name for p in out.iterdir() if p.is_file())
    return manifest

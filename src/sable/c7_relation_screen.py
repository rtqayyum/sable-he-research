"""C7 relation and readiness estimator.

The estimator is deliberately conservative.  It treats C7 standard block bases
as relation-free within each block and screens C7 random bases for relations up
to the configured weight.  It also reports CLPN row-difference surfaces because
those remain present for any CLPN compaction key.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import asdict, dataclass
from typing import Any

from .clpn_c7_screened import build_screened_basis_key, estimate_c7_key, relation_free_up_to
from .field import qary_piling_up
from .params import PRESETS, SableParams
from .qary_lpn_estimator import estimate_qary_lpn_surface
from .regev import extended_secret


def _jsonable_float(x: float | int | None) -> float | int | str | None:
    if x is None:
        return None
    if isinstance(x, int):
        return x
    if math.isinf(x):
        return "inf" if x > 0 else "-inf"
    if math.isnan(x):
        return "nan"
    return x


@dataclass(frozen=True)
class C7RelationReport:
    params: dict[str, Any]
    c7_key_estimate: dict[str, Any]
    mode: str
    block_size: int
    basis_size: int | None
    relation_screen_weight: int
    sampled_basis_min_relation_checked_to: int
    sampled_basis_passes_relation_screen: bool
    public_entries: int
    public_clpn_rows: int
    row_difference_samples: int
    row_difference_noise: float
    expansion_key_rows: int
    lpn_screens: list[dict[str, Any]]
    minimum_screen_bits: float | None
    verdict: str
    blockers: list[str]
    interpretation: str

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["row_difference_noise"] = _jsonable_float(self.row_difference_noise)
        d["minimum_screen_bits"] = _jsonable_float(self.minimum_screen_bits)
        return d


def _screen_bits(screen: dict[str, Any]) -> float | None:
    value = screen.get("conservative_min_bits")
    if value is None:
        return None
    if value == "inf":
        return float("inf")
    if value == "-inf":
        return float("-inf")
    return float(value)


def _dummy_tilde_s(params: SableParams) -> list[int]:
    # Only the vector length matters for relation-surface screening.  Use a
    # deterministic non-secret vector to instantiate the public basis shape.
    return extended_secret([0] * params.n, params.q)


def estimate_c7_relations(
    params: SableParams,
    *,
    block_size: int | None = None,
    mode: str = "standard",
    basis_size: int | None = None,
    max_terms_per_block: int | None = None,
    relation_screen_weight: int = 3,
    target_bits: float = 128.0,
    seed: int = 777,
) -> C7RelationReport:
    ell = params.c2_block_size if block_size is None else block_size
    est = estimate_c7_key(
        params,
        block_size=ell,
        mode=mode,  # type: ignore[arg-type]
        basis_size=basis_size,
        max_terms_per_block=max_terms_per_block,
        relation_screen_weight=relation_screen_weight,
    )
    rng = random.Random(seed)
    dummy_r = [0] * params.n_c
    key = build_screened_basis_key(
        _dummy_tilde_s(params),
        dummy_r,
        params,
        rng,
        block_size=ell,
        mode=mode,  # type: ignore[arg-type]
        basis_size=basis_size,
        max_terms_per_block=max_terms_per_block,
        relation_screen_weight=relation_screen_weight,
    )
    relation_ok = all(relation_free_up_to(params.q, basis, relation_screen_weight) for basis in key.bases)
    public_rows = key.public_clpn_rows
    row_diff_samples = key.public_entries * (params.m_c * (params.m_c - 1) // 2)
    eta2 = qary_piling_up(params.q, params.eta_c, 2)
    expansion_rows = params.N * params.N
    screens: list[dict[str, Any]] = [
        estimate_qary_lpn_surface(
            name="C7_expansion_key_sparse_LPN_rows",
            n=params.n,
            q=params.q,
            eta=params.eta,
            samples=expansion_rows,
            row_weight=params.k,
            target_bits=target_bits,
        ),
        estimate_qary_lpn_surface(
            name="C7_CLPN_row_differences",
            n=params.n_c,
            q=params.q,
            eta=eta2,
            samples=max(1, row_diff_samples),
            row_weight=None,
            target_bits=target_bits,
        ),
    ]
    bits = [_screen_bits(screen) for screen in screens]
    finite_bits = [b for b in bits if b is not None and math.isfinite(b)]
    min_bits = min(finite_bits) if finite_bits else None
    blockers: list[str] = []
    if not relation_ok:
        blockers.append("sampled C7 basis has a relation within the configured screen weight")
    for screen in screens:
        b = _screen_bits(screen)
        if b is not None and b < target_bits:
            blockers.append(f"{screen['name']} below target: {b:.2f} bits")
        for warning in screen.get("warnings", []):
            if "zero noise" in warning or "below" in warning or "large public" in warning or "sample" in warning:
                blockers.append(f"{screen['name']}: {warning}")
    verdict = "passes-c7-relation-screen" if not blockers else "research-only-parameters"
    return C7RelationReport(
        params=asdict(params),
        c7_key_estimate=est,
        mode=mode,
        block_size=ell,
        basis_size=basis_size,
        relation_screen_weight=relation_screen_weight,
        sampled_basis_min_relation_checked_to=relation_screen_weight,
        sampled_basis_passes_relation_screen=relation_ok,
        public_entries=key.public_entries,
        public_clpn_rows=public_rows,
        row_difference_samples=row_diff_samples,
        row_difference_noise=eta2,
        expansion_key_rows=expansion_rows,
        lpn_screens=screens,
        minimum_screen_bits=min_bits,
        verdict=verdict,
        blockers=blockers,
        interpretation=(
            "C7 removes the full projective dictionary as the main candidate. "
            "The standard-basis mode has no intra-block public mask relations and is the conservative ready baseline. "
            "screened_random is experimental and must pass relation screens before being used in claims. "
            "This estimator is a screening tool, not a cryptanalytic proof."
        ),
    )


def format_c7_report(report: C7RelationReport) -> str:
    lines = [
        f"C7 relation-screen report for {report.params['name']}",
        f"mode={report.mode} block_size={report.block_size} basis_size={report.basis_size} relation_screen_weight={report.relation_screen_weight}",
        f"public entries={report.public_entries} public CLPN rows={report.public_clpn_rows}",
        f"row-difference samples={report.row_difference_samples} eta2={report.row_difference_noise:.6g}",
        f"sampled relation screen passed={report.sampled_basis_passes_relation_screen}",
        f"minimum finite screen bits={report.minimum_screen_bits if report.minimum_screen_bits is not None else 'n/a'}",
        f"verdict={report.verdict}",
        "",
        "C7 key estimate:",
    ]
    for key, value in report.c7_key_estimate.items():
        lines.append(f"  {key}: {value}")
    lines.append("")
    lines.append("LPN screens:")
    for screen in report.lpn_screens:
        lines.append(
            f"  - {screen['name']}: n={screen['n']} samples={screen['samples']} eta={screen['eta']} min_bits={screen.get('conservative_min_bits')} passes={screen.get('passes_target_screen')}"
        )
        for warning in screen.get("warnings", [])[:4]:
            lines.append(f"      warning: {warning}")
    if report.blockers:
        lines.append("")
        lines.append("Blockers / notes:")
        for blocker in report.blockers[:20]:
            lines.append(f"  - {blocker}")
    lines.append("")
    lines.append(report.interpretation)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="C7 relation-screen estimator")
    parser.add_argument("--preset", default="c7_standard_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--mode", default="standard", choices=["standard", "screened_random"])
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--basis-size", type=int, default=None)
    parser.add_argument("--max-terms", type=int, default=None)
    parser.add_argument("--relation-screen-weight", type=int, default=3)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = estimate_c7_relations(
        PRESETS[args.preset],
        block_size=args.block_size,
        mode=args.mode,
        basis_size=args.basis_size,
        max_terms_per_block=args.max_terms,
        relation_screen_weight=args.relation_screen_weight,
        target_bits=args.target_bits,
    )
    if args.json:
        print(json.dumps(report.to_jsonable(), indent=2))
    else:
        print(format_c7_report(report))


if __name__ == "__main__":
    main()

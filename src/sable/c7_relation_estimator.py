"""C7 screened-basis public-surface estimator.

C7 replaces C4's full projective basis by coordinate-plus-random screened
bases.  This module counts public rows, searches for low-weight relations in
small validation bases, and applies the existing q-ary-LPN surface screen to
row differences and relation-derived samples.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import asdict, dataclass
from typing import Any

from .additive_basis import find_low_weight_relation
from .clpn_c7_screened import build_screened_basis, estimate_c7_key
from .field import qary_piling_up
from .params import PRESETS, SableParams
from .qary_lpn_estimator import estimate_qary_lpn_surface


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


def c7_widths(N: int, block_size: int) -> list[int]:
    if N <= 0 or block_size <= 0:
        raise ValueError("invalid widths")
    return [min(block_size, N - start) for start in range(0, N, block_size)]


@dataclass(frozen=True)
class C7BlockProfile:
    width: int
    entries: int
    kernel_dimension: int
    screened_relation_weight_below: int
    low_weight_relations_found: int
    minimum_relation_weight_observed: int | None
    relation_noise_at_observed_weight: float | None
    warning: str

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["relation_noise_at_observed_weight"] = _jsonable_float(self.relation_noise_at_observed_weight)
        return d


@dataclass(frozen=True)
class C7SurfaceCounts:
    q: int
    N: int
    block_size: int
    num_blocks: int
    c7_entries: int
    c4_projective_entries: int
    c2_full_dictionary_entries: int
    c7_public_clpn_rows: int
    row_difference_samples: int
    row_difference_noise: float
    screened_relation_samples_rank_cap: int
    relation_noise_for_min_weight: float | None
    expansion_key_rows: int
    block_profiles: list[C7BlockProfile]

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["row_difference_noise"] = _jsonable_float(self.row_difference_noise)
        d["relation_noise_for_min_weight"] = _jsonable_float(self.relation_noise_for_min_weight)
        d["block_profiles"] = [b.to_jsonable() for b in self.block_profiles]
        return d


@dataclass(frozen=True)
class C7AttackReport:
    params: dict[str, Any]
    target_bits: float
    counts: C7SurfaceCounts
    lpn_screens: list[dict[str, Any]]
    minimum_screen_bits: float | None
    verdict: str
    blockers: list[str]
    interpretation: str

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "params": self.params,
            "target_bits": self.target_bits,
            "counts": self.counts.to_jsonable(),
            "lpn_screens": self.lpn_screens,
            "minimum_screen_bits": _jsonable_float(self.minimum_screen_bits),
            "verdict": self.verdict,
            "blockers": self.blockers,
            "interpretation": self.interpretation,
        }


def _entry_count(q: int, width: int, target_size: int | None, extra_vectors: int) -> int:
    projective = (q**width - 1) // (q - 1)
    if width <= 1:
        return width
    if target_size is not None:
        return max(width, min(target_size, projective))
    return max(width, min(width + extra_vectors, projective))


def surface_counts(
    params: SableParams,
    *,
    block_size: int | None = None,
    target_size: int | None = None,
    extra_vectors: int = 1,
    min_relation_weight: int | None = None,
    search_relation_weight: int | None = None,
    seed: int = 777,
) -> C7SurfaceCounts:
    q = params.q
    N = params.N
    ell = params.c2_block_size if block_size is None else block_size
    widths = c7_widths(N, ell)
    rel_w = ell + 1 if min_relation_weight is None else min_relation_weight
    search_w = rel_w if search_relation_weight is None else search_relation_weight
    rng = random.Random(seed)
    block_profiles: list[C7BlockProfile] = []
    c7_entries = 0
    c2_entries = 0
    c4_entries = 0
    relation_rank_cap = 0
    min_observed_relation: int | None = None
    for width in widths:
        entries = _entry_count(q, width, target_size, extra_vectors)
        c7_entries += entries
        c2_entries += q**width - 1
        c4_entries += (q**width - 1) // (q - 1)
        kernel_dim = max(0, entries - width)
        local_min_rel: int | None = None
        relations_found = 0
        warning = "coordinate-only block; no surplus-mask relation surface"
        if width > 1 and entries > width:
            basis = build_screened_basis(
                q,
                width,
                rng,
                target_size=entries,
                min_relation_weight=min(rel_w, width + 1),
                max_attempts=20000,
            )
            for w in range(2, max(2, search_w) + 1):
                rels = find_low_weight_relation(q, basis, w, limit=1)
                if rels:
                    local_min_rel = w
                    relations_found = 1
                    break
            if local_min_rel is None:
                warning = f"no relation found up to weight {search_w}; kernel dimension is still {kernel_dim}"
            elif local_min_rel < rel_w:
                warning = f"unexpected relation below screen target: weight {local_min_rel}"
            else:
                warning = f"first relation found at screened/unavoidable weight {local_min_rel}"
            relation_rank_cap += kernel_dim
        if local_min_rel is not None:
            if min_observed_relation is None or local_min_rel < min_observed_relation:
                min_observed_relation = local_min_rel
        block_profiles.append(
            C7BlockProfile(
                width=width,
                entries=entries,
                kernel_dimension=kernel_dim,
                screened_relation_weight_below=max(0, rel_w - 1),
                low_weight_relations_found=relations_found,
                minimum_relation_weight_observed=local_min_rel,
                relation_noise_at_observed_weight=qary_piling_up(q, params.eta_c, local_min_rel) if local_min_rel else None,
                warning=warning,
            )
        )
    row_diff = c7_entries * (params.m_c * (params.m_c - 1) // 2)
    eta2 = qary_piling_up(q, params.eta_c, 2)
    relation_noise = qary_piling_up(q, params.eta_c, min_observed_relation) if min_observed_relation else None
    return C7SurfaceCounts(
        q=q,
        N=N,
        block_size=ell,
        num_blocks=len(widths),
        c7_entries=c7_entries,
        c4_projective_entries=c4_entries,
        c2_full_dictionary_entries=c2_entries,
        c7_public_clpn_rows=c7_entries * params.m_c,
        row_difference_samples=row_diff,
        row_difference_noise=eta2,
        screened_relation_samples_rank_cap=relation_rank_cap * params.m_c,
        relation_noise_for_min_weight=relation_noise,
        expansion_key_rows=N * N,
        block_profiles=block_profiles,
    )


def _screen_bits(screen: dict[str, Any]) -> float | None:
    value = screen.get("conservative_min_bits")
    if value is None:
        return None
    if value == "inf":
        return float("inf")
    if value == "-inf":
        return float("-inf")
    return float(value)


def estimate_c7_relations(
    params: SableParams,
    *,
    block_size: int | None = None,
    target_size: int | None = None,
    extra_vectors: int = 1,
    min_relation_weight: int | None = None,
    target_bits: float = 128.0,
    seed: int = 777,
) -> C7AttackReport:
    counts = surface_counts(
        params,
        block_size=block_size,
        target_size=target_size,
        extra_vectors=extra_vectors,
        min_relation_weight=min_relation_weight,
        seed=seed,
    )
    screens: list[dict[str, Any]] = []
    screens.append(
        estimate_qary_lpn_surface(
            name="C7_expansion_key_sparse_LPN_rows",
            n=params.n,
            q=params.q,
            eta=params.eta,
            samples=counts.expansion_key_rows,
            row_weight=params.k,
            target_bits=target_bits,
        )
    )
    screens.append(
        estimate_qary_lpn_surface(
            name="C7_CLPN_row_differences",
            n=params.n_c,
            q=params.q,
            eta=counts.row_difference_noise,
            samples=max(1, counts.row_difference_samples),
            row_weight=None,
            target_bits=target_bits,
        )
    )
    if counts.screened_relation_samples_rank_cap > 0 and counts.relation_noise_for_min_weight is not None:
        screens.append(
            estimate_qary_lpn_surface(
                name="C7_screened_relation_rows_rank_capped",
                n=params.n_c,
                q=params.q,
                eta=counts.relation_noise_for_min_weight,
                samples=max(1, counts.screened_relation_samples_rank_cap),
                row_weight=None,
                target_bits=target_bits,
            )
        )
    bits = [_screen_bits(s) for s in screens]
    finite = [b for b in bits if b is not None and math.isfinite(b)]
    min_bits = min(finite) if finite else None
    blockers: list[str] = []
    for profile in counts.block_profiles:
        if profile.minimum_relation_weight_observed is not None and profile.minimum_relation_weight_observed < profile.screened_relation_weight_below + 1:
            blockers.append(f"block width {profile.width} relation below screen target")
    for screen in screens:
        b = _screen_bits(screen)
        if b is not None and b < target_bits:
            blockers.append(f"{screen['name']} below target: {b:.2f} bits")
        for warning in screen.get("warnings", []):
            if "zero noise" in warning or "below" in warning or "large public" in warning:
                blockers.append(f"{screen['name']}: {warning}")
    verdict = "passes-c7-structural-screen" if not blockers else "requires-parameter-work"
    return C7AttackReport(
        params=asdict(params),
        target_bits=target_bits,
        counts=counts,
        lpn_screens=screens,
        minimum_screen_bits=min_bits,
        verdict=verdict,
        blockers=blockers,
        interpretation=(
            "C7 avoids the complete projective line surface by publishing only coordinate vectors plus screened random masks. "
            "It is correctness-safe because the coordinate basis alone spans every block, and it is structurally safer than C4 because low-weight relations are explicitly screened. "
            "This is not a proof of concrete security; it is a relation-surface filter that must be combined with LPN attack estimation."
        ),
    )


def format_c7_report(report: C7AttackReport) -> str:
    p = report.params
    c = report.counts
    lines = [
        f"C7 screened-basis surface screen for {p['name']}  target={report.target_bits:.0f} bits",
        f"q={p['q']} N={c.N} block_size={c.block_size} blocks={c.num_blocks} n_c={p['n_c']} m_c={p['m_c']} eta_c={p['eta_c']}",
        f"C7 entries={c.c7_entries}  C4 projective entries={c.c4_projective_entries}  C2 entries={c.c2_full_dictionary_entries}",
        f"C7 public CLPN rows={c.c7_public_clpn_rows}",
        f"Row-difference samples={c.row_difference_samples} eta2={c.row_difference_noise:.6g}",
        f"Rank-capped screened relation rows={c.screened_relation_samples_rank_cap} eta_rel={c.relation_noise_for_min_weight}",
        f"Minimum finite screen bits={report.minimum_screen_bits if report.minimum_screen_bits is not None else 'n/a'}",
        f"Verdict={report.verdict}",
        "",
        "Block profiles:",
    ]
    for block in c.block_profiles[:10]:
        lines.append(
            f"  - width={block.width} entries={block.entries} kernel_dim={block.kernel_dimension} "
            f"min_relation={block.minimum_relation_weight_observed} note={block.warning}"
        )
    if len(c.block_profiles) > 10:
        lines.append(f"  - ... {len(c.block_profiles) - 10} more blocks")
    lines.append("")
    lines.append("LPN screens:")
    for screen in report.lpn_screens:
        lines.append(
            f"  - {screen['name']}: n={screen['n']} samples={screen['samples']} eta={screen['eta']} "
            f"min_bits={screen['conservative_min_bits']} passes={screen['passes_target_screen']}"
        )
        for warning in screen.get("warnings", [])[:4]:
            lines.append(f"      warning: {warning}")
    if report.blockers:
        lines.append("")
        lines.append("Blockers / parameter work:")
        for item in report.blockers[:20]:
            lines.append(f"  - {item}")
    lines.append("")
    lines.append(report.interpretation)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="C7 screened-basis relation-surface estimator")
    parser.add_argument("--preset", default="c4_projective_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=4)
    parser.add_argument("--target-size", type=int, default=None)
    parser.add_argument("--extra-vectors", type=int, default=1)
    parser.add_argument("--min-relation-weight", type=int, default=None)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--seed", type=int, default=777)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = estimate_c7_relations(
        PRESETS[args.preset],
        block_size=args.block_size,
        target_size=args.target_size,
        extra_vectors=args.extra_vectors,
        min_relation_weight=args.min_relation_weight,
        target_bits=args.target_bits,
        seed=args.seed,
    )
    if args.json:
        print(json.dumps(report.to_jsonable(), indent=2))
    else:
        print(format_c7_report(report))


if __name__ == "__main__":
    main()

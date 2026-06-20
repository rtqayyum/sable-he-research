"""C6 relation-surface estimator for C4 projective compaction.

C4 projective compaction stores one CLPN encryption for each projective
representative in every secret-key block.  This reduces entries relative to a
full C2/C3 dictionary, but the public projective set contains many low-weight
linear dependencies.  Every projective line has q+1 points, and every triple of
distinct points on such a line is linearly dependent.  Combining the
corresponding CLPN ciphertexts produces a known-zero CLPN/LPN-style sample
surface with q-ary noise equal to the sum of three original noise variables.

This module does not certify security.  It gives a transparent, repeatable
screen that separates:

* normal sparse-LPN expansion-key rows;
* C4 CLPN row-difference samples that remove the unknown message shift;
* raw weight-3 projective relation rows;
* rank-capped weight-3 relation rows, capped by the dimension of the relation
  space of the public projective block.

The raw count is an upper bound on low-weight relation combinations.  The
rank-capped count is a conservative independence proxy.  Both should be
reported because they reveal different attack surfaces.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Any

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


def c4_widths(N: int, block_size: int) -> list[int]:
    if N <= 0:
        raise ValueError("N must be positive")
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    return [min(block_size, N - start) for start in range(0, N, block_size)]


def projective_point_count(q: int, width: int) -> int:
    if q <= 1:
        raise ValueError("q must be at least two")
    if width <= 0:
        return 0
    return (q**width - 1) // (q - 1)


def gaussian_binomial_2(q: int, width: int) -> int:
    """Number of 2-dimensional linear subspaces of F_q^width.

    This is the Gaussian binomial coefficient [width choose 2]_q.  It equals
    the number of projective lines in PG(width-1,q).  For width < 2 there are
    no projective lines.
    """
    if q <= 1:
        raise ValueError("q must be at least two")
    if width < 2:
        return 0
    numerator = (q**width - 1) * (q ** (width - 1) - 1)
    denominator = (q**2 - 1) * (q - 1)
    return numerator // denominator


def weight3_projective_relations(q: int, width: int) -> int:
    """Raw number of projective-line triples in one block.

    In PG(width-1,q), every projective line has q+1 points.  Every set of
    three distinct points on a line is linearly dependent, producing a
    weight-3 relation among projective representatives up to nonzero scalars.
    """
    if width < 2:
        return 0
    return gaussian_binomial_2(q, width) * math.comb(q + 1, 3)


def projective_relation_space_dimension(q: int, width: int) -> int:
    """Dimension of all linear relations among projective representatives.

    If M projective representatives span F_q^width, then the kernel dimension
    of the linear map F_q^M -> F_q^width is M-width.  This is not the number of
    low-weight relations; it is an independence cap for relation-derived
    ciphertexts in one block.
    """
    if width <= 0:
        return 0
    return max(0, projective_point_count(q, width) - width)


@dataclass(frozen=True)
class C6BlockProfile:
    width: int
    projective_entries: int
    relation_space_dimension: int
    projective_lines: int
    raw_weight3_relations: int
    weight3_relation_noise: float
    warning: str

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["weight3_relation_noise"] = _jsonable_float(self.weight3_relation_noise)
        return d


@dataclass(frozen=True)
class C6SurfaceCounts:
    q: int
    N: int
    block_size: int
    num_blocks: int
    c4_projective_entries: int
    c2_full_dictionary_entries: int
    c4_vs_c2_entry_ratio: float
    c4_public_clpn_rows: int
    row_difference_samples: int
    row_difference_noise: float
    raw_weight3_relations: int
    raw_weight3_relation_rows: int
    rank_capped_relation_dimension: int
    rank_capped_relation_rows: int
    weight3_relation_noise: float
    expansion_key_rows: int
    block_profiles: list[C6BlockProfile]

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        d["c4_vs_c2_entry_ratio"] = _jsonable_float(self.c4_vs_c2_entry_ratio)
        d["row_difference_noise"] = _jsonable_float(self.row_difference_noise)
        d["weight3_relation_noise"] = _jsonable_float(self.weight3_relation_noise)
        d["block_profiles"] = [b.to_jsonable() for b in self.block_profiles]
        return d


@dataclass(frozen=True)
class C6AttackReport:
    params: dict[str, Any]
    target_bits: float
    counts: C6SurfaceCounts
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


def surface_counts(params: SableParams, *, block_size: int | None = None) -> C6SurfaceCounts:
    q = params.q
    N = params.N
    ell = params.c2_block_size if block_size is None else block_size
    widths = c4_widths(N, ell)
    block_profiles: list[C6BlockProfile] = []
    entries_total = 0
    c2_entries_total = 0
    rel_total = 0
    rel_dim_total = 0
    lines_total = 0
    eta3 = qary_piling_up(q, params.eta_c, 3)
    for width in widths:
        entries = projective_point_count(q, width)
        c2_entries = q**width - 1
        rel_dim = projective_relation_space_dimension(q, width)
        lines = gaussian_binomial_2(q, width)
        raw_rel = weight3_projective_relations(q, width)
        entries_total += entries
        c2_entries_total += c2_entries
        rel_total += raw_rel
        rel_dim_total += rel_dim
        lines_total += lines
        if width >= 2:
            warning = "min relation weight is 3; relation-derived zero-message samples exist"
        else:
            warning = "no weight-3 projective relation in width-one block"
        block_profiles.append(
            C6BlockProfile(
                width=width,
                projective_entries=entries,
                relation_space_dimension=rel_dim,
                projective_lines=lines,
                raw_weight3_relations=raw_rel,
                weight3_relation_noise=eta3 if raw_rel else 0.0,
                warning=warning,
            )
        )
    row_diff = entries_total * (params.m_c * (params.m_c - 1) // 2)
    eta2 = qary_piling_up(q, params.eta_c, 2)
    return C6SurfaceCounts(
        q=q,
        N=N,
        block_size=ell,
        num_blocks=len(widths),
        c4_projective_entries=entries_total,
        c2_full_dictionary_entries=c2_entries_total,
        c4_vs_c2_entry_ratio=(entries_total / c2_entries_total) if c2_entries_total else 0.0,
        c4_public_clpn_rows=entries_total * params.m_c,
        row_difference_samples=row_diff,
        row_difference_noise=eta2,
        raw_weight3_relations=rel_total,
        raw_weight3_relation_rows=rel_total * params.m_c,
        rank_capped_relation_dimension=rel_dim_total,
        rank_capped_relation_rows=rel_dim_total * params.m_c,
        weight3_relation_noise=eta3,
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


def estimate_c6_relations(
    params: SableParams,
    *,
    block_size: int | None = None,
    target_bits: float = 128.0,
    include_raw_relation_screen: bool = True,
) -> C6AttackReport:
    counts = surface_counts(params, block_size=block_size)
    screens: list[dict[str, Any]] = []

    screens.append(
        estimate_qary_lpn_surface(
            name="C6_expansion_key_sparse_LPN_rows",
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
            name="C6_C4_CLPN_row_differences",
            n=params.n_c,
            q=params.q,
            eta=counts.row_difference_noise,
            samples=max(1, counts.row_difference_samples),
            row_weight=None,
            target_bits=target_bits,
        )
    )
    screens.append(
        estimate_qary_lpn_surface(
            name="C6_C4_weight3_relations_rank_capped",
            n=params.n_c,
            q=params.q,
            eta=counts.weight3_relation_noise,
            samples=max(1, counts.rank_capped_relation_rows),
            row_weight=None,
            target_bits=target_bits,
        )
    )
    if include_raw_relation_screen:
        screens.append(
            estimate_qary_lpn_surface(
                name="C6_C4_weight3_relations_raw_upper_bound",
                n=params.n_c,
                q=params.q,
                eta=counts.weight3_relation_noise,
                samples=max(1, counts.raw_weight3_relation_rows),
                row_weight=None,
                target_bits=target_bits,
            )
        )

    bits = [_screen_bits(s) for s in screens]
    finite_bits = [b for b in bits if b is not None and math.isfinite(b)]
    min_bits = min(finite_bits) if finite_bits else None
    blockers: list[str] = []
    for screen in screens:
        b = _screen_bits(screen)
        if b is not None and b < target_bits:
            blockers.append(f"{screen['name']} below target: {b:.2f} bits")
        for warning in screen.get("warnings", []):
            if "zero noise" in warning or "below" in warning or "large public" in warning or "sample" in warning:
                blockers.append(f"{screen['name']}: {warning}")
    if counts.raw_weight3_relations > 0:
        blockers.append(
            "C4 projective blocks of width >= 2 expose weight-3 zero-message relation combinations; this must be addressed before security claims."
        )
    verdict = "reject-for-current-security-claim" if blockers else "passes-c6-screen"
    return C6AttackReport(
        params=asdict(params),
        target_bits=target_bits,
        counts=counts,
        lpn_screens=screens,
        minimum_screen_bits=min_bits,
        verdict=verdict,
        blockers=blockers,
        interpretation=(
            "C6 is a diagnostic screening layer, not a certified cryptanalysis result. "
            "It corrects the C5 relation-weight heuristic by counting weight-3 projective-line relations in C4. "
            "A security-grade design should avoid full projective block dictionaries of width >= 2 or prove that the resulting relation-derived samples do not help known LPN attacks."
        ),
    )


def format_c6_report(report: C6AttackReport) -> str:
    p = report.params
    c = report.counts
    lines = [
        f"C6 relation-surface screen for {p['name']}  target={report.target_bits:.0f} bits",
        f"q={p['q']} N={c.N} block_size={c.block_size} blocks={c.num_blocks} n_c={p['n_c']} m_c={p['m_c']} eta_c={p['eta_c']}",
        f"C4 entries={c.c4_projective_entries}  C2 entries={c.c2_full_dictionary_entries}  C4/C2={c.c4_vs_c2_entry_ratio:.6g}",
        f"C4 public CLPN rows={c.c4_public_clpn_rows}",
        f"Row-difference samples={c.row_difference_samples}  eta2={c.row_difference_noise:.6g}",
        f"Raw weight-3 relations={c.raw_weight3_relations}  rows={c.raw_weight3_relation_rows}  eta3={c.weight3_relation_noise:.6g}",
        f"Rank-capped relation dimension={c.rank_capped_relation_dimension}  rows={c.rank_capped_relation_rows}",
        f"Minimum finite screen bits={report.minimum_screen_bits if report.minimum_screen_bits is not None else 'n/a'}",
        f"Verdict={report.verdict}",
        "",
        "LPN screens:",
    ]
    for screen in report.lpn_screens:
        b = screen.get("conservative_min_bits")
        lines.append(
            f"  - {screen['name']}: n={screen['n']} samples={screen['samples']} eta={screen['eta']} min_bits={b} passes={screen['passes_target_screen']}"
        )
        for warning in screen.get("warnings", [])[:4]:
            lines.append(f"      warning: {warning}")
    if report.blockers:
        lines.append("")
        lines.append("Blockers / required follow-up:")
        for item in report.blockers[:20]:
            lines.append(f"  - {item}")
        if len(report.blockers) > 20:
            lines.append(f"  - ... {len(report.blockers) - 20} additional blocker notes omitted")
    lines.append("")
    lines.append(report.interpretation)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="C6 C4-projective relation-surface estimator")
    parser.add_argument("--preset", default="c4_projective_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--no-raw", action="store_true", help="omit raw relation upper-bound screen")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = estimate_c6_relations(
        PRESETS[args.preset],
        block_size=args.block_size,
        target_bits=args.target_bits,
        include_raw_relation_screen=not args.no_raw,
    )
    if args.json:
        print(json.dumps(report.to_jsonable(), indent=2))
    else:
        print(format_c6_report(report))


if __name__ == "__main__":
    main()

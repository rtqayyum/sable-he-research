"""C5 attack-surface estimator for C4 projective compaction.

This is a conservative diagnostic, not a cryptanalytic proof.  It tracks the
public q-ary-LPN sample surface introduced by the C4 projective basis, the
lowest expected linear-relation weight inside each projective block, and the
noise level of zero-message relation combinations.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass

from .field import qary_piling_up, repetition_failure_bound
from .params import PRESETS, SableParams


def _log2_int(x: int) -> float:
    return math.log2(x) if x > 0 else float("-inf")


def projective_entries(q: int, width: int) -> int:
    if width <= 0:
        return 0
    return (q**width - 1) // (q - 1)


def widths_for_N(N: int, block_size: int) -> list[int]:
    return [min(block_size, N - start) for start in range(0, N, block_size)]


def relation_weight_projective(width: int) -> int:
    """Heuristic minimum relation weight for full projective representatives.

    One representative per 1-D subspace removes weight-2 same-line relations.
    In a width-dimensional vector space, any width+1 vectors are dependent,
    while generic subsets of size <= width are independent.  For complete
    projective sets this is a useful first screen; special low-weight relations
    can still exist and should be checked empirically for concrete bases.
    """
    return width + 1


def log2_choose(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    if k == 0 or k == n:
        return 0.0
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


@dataclass(frozen=True)
class C5BlockSurface:
    width: int
    projective_entries: int
    public_clpn_rows: int
    min_relation_weight_heuristic: int
    relation_noise_rate: float
    relation_repetition_failure_bound: float
    log2_relation_choice_upper_bound: float
    flag: str


@dataclass(frozen=True)
class C5SurfaceReport:
    params: str
    q: int
    N: int
    block_size: int
    n_c: int
    m_c: int
    eta_c: float
    num_blocks: int
    c4_public_entries: int
    c4_public_clpn_rows: int
    c4_dense_public_field_elements: int
    c2_public_entries_if_full_dictionary: int
    c4_vs_c2_entry_ratio: float
    max_active_blocks: int
    c4_compaction_terms_bound: int
    c4_compaction_noise_bound: float
    c4_compaction_repetition_failure_bound: float
    block_surfaces: list[C5BlockSurface]
    global_flag: str
    warning: str


def estimate_c4_surface(params: SableParams, *, block_size: int | None = None, max_terms_per_block: int = 1) -> C5SurfaceReport:
    q = params.q
    N = params.N
    ell = params.c2_block_size if block_size is None else block_size
    widths = widths_for_N(N, ell)
    c4_entries = sum(projective_entries(q, w) for w in widths)
    c2_entries = sum(q**w - 1 for w in widths)
    max_active_blocks = len(widths)
    term_bound = max_active_blocks * max_terms_per_block
    compaction_noise = qary_piling_up(q, params.eta_c, term_bound)
    compaction_fail = repetition_failure_bound(params.m_c, compaction_noise)

    blocks: list[C5BlockSurface] = []
    flags: list[str] = []
    for w in widths:
        entries = projective_entries(q, w)
        rel_w = relation_weight_projective(w)
        rel_noise = qary_piling_up(q, params.eta_c, rel_w)
        rel_fail = repetition_failure_bound(params.m_c, rel_noise)
        log2_rel = log2_choose(entries, rel_w) + max(0, rel_w - 1) * math.log2(max(1, q - 1))
        if rel_w <= 3:
            flag = "watch: many low-weight projective relations"
        elif rel_noise < 0.01 and entries * params.m_c > params.n_c:
            flag = "watch: low-noise large-sample relation surface"
        else:
            flag = "ok-for-screen"
        flags.append(flag)
        blocks.append(
            C5BlockSurface(
                width=w,
                projective_entries=entries,
                public_clpn_rows=entries * params.m_c,
                min_relation_weight_heuristic=rel_w,
                relation_noise_rate=rel_noise,
                relation_repetition_failure_bound=rel_fail,
                log2_relation_choice_upper_bound=log2_rel,
                flag=flag,
            )
        )

    if any(f.startswith("watch") for f in flags):
        global_flag = "watch"
    else:
        global_flag = "ok-for-screen"
    return C5SurfaceReport(
        params=params.name,
        q=q,
        N=N,
        block_size=ell,
        n_c=params.n_c,
        m_c=params.m_c,
        eta_c=params.eta_c,
        num_blocks=len(widths),
        c4_public_entries=c4_entries,
        c4_public_clpn_rows=c4_entries * params.m_c,
        c4_dense_public_field_elements=c4_entries * params.m_c * (params.n_c + 1),
        c2_public_entries_if_full_dictionary=c2_entries,
        c4_vs_c2_entry_ratio=(c4_entries / c2_entries) if c2_entries else 0.0,
        max_active_blocks=max_active_blocks,
        c4_compaction_terms_bound=term_bound,
        c4_compaction_noise_bound=compaction_noise,
        c4_compaction_repetition_failure_bound=compaction_fail,
        block_surfaces=blocks,
        global_flag=global_flag,
        warning="Diagnostic screen only; not a security proof or a certified parameter estimator.",
    )


def report_to_text(report: C5SurfaceReport) -> str:
    lines = [
        f"C5 C4-projective attack-surface screen: preset={report.params}",
        f"q={report.q} N={report.N} block_size={report.block_size} blocks={report.num_blocks}",
        f"public C4 entries={report.c4_public_entries}",
        f"public CLPN rows={report.c4_public_clpn_rows}",
        f"dense public field elements={report.c4_dense_public_field_elements}",
        f"C2 full-dictionary entries={report.c2_public_entries_if_full_dictionary}",
        f"C4/C2 entry ratio={report.c4_vs_c2_entry_ratio:.6g}",
        f"compaction terms bound={report.c4_compaction_terms_bound}",
        f"compaction q-ary noise bound={report.c4_compaction_noise_bound:.6g}",
        f"compaction repetition failure bound={report.c4_compaction_repetition_failure_bound:.6g}",
        f"global flag={report.global_flag}",
        "block surfaces:",
    ]
    for i, b in enumerate(report.block_surfaces[:12]):
        lines.append(
            f"  block[{i}] width={b.width} entries={b.projective_entries} rows={b.public_clpn_rows} "
            f"rel_w={b.min_relation_weight_heuristic} rel_noise={b.relation_noise_rate:.6g} "
            f"log2_rel_choices<={b.log2_relation_choice_upper_bound:.3f} flag={b.flag}"
        )
    if len(report.block_surfaces) > 12:
        lines.append(f"  ... {len(report.block_surfaces)-12} more blocks omitted")
    lines.append(report.warning)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="C5 screen for C4 projective compaction public surface")
    parser.add_argument("--preset", default="c4_projective_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--max-terms-per-block", type=int, default=1)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = estimate_c4_surface(PRESETS[args.preset], block_size=args.block_size, max_terms_per_block=args.max_terms_per_block)
    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print(report_to_text(report))


if __name__ == "__main__":
    main()

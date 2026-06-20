"""C5 public-surface and relation screens for C4 projective compaction.

The estimator focuses on the new surface introduced by C4: projective basis
ciphertexts for blockwise compaction.  It does not certify security.  It is a
repeatable red-flag screen for sample volume, low-weight relations, and storage
tradeoffs.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass

from .additive_basis import projective_count
from .attack_estimator import LPNInstance, estimate_instance, instance_estimate_to_dict
from .c4_estimator import compare as compare_c4
from .params import SableParams


def _block_widths(N: int, block_size: int) -> list[int]:
    return [min(block_size, N - start) for start in range(0, N, block_size)]


@dataclass(frozen=True)
class C4SurfaceReport:
    params: dict
    block_size: int
    block_widths: list[int]
    c4_projective_entries: int
    c2_full_dictionary_entries: int
    reduction_vs_c2: float
    sparse_lpn_expansion_rows: int
    clpn_compaction_rows: int
    clpn_dimension: int
    row_difference_surfaces: int
    pair_relation_surfaces_upper_bound: int
    minimum_linear_relation_weight_screen: int
    relation_warning: str
    best_feasible_attack_screen_bits: float | None
    lpn_instances: list[dict]
    interpretation: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def c4_min_relation_weight_screen(q: int, width: int) -> int:
    """Return a conservative low-weight relation screen for projective PG(width-1,q).

    In width 1 there are no nontrivial projective entries beyond one point. In
    width 2, any three projective representatives in a 2D vector space are
    linearly dependent, and for the standard representative set used here there
    are weight-3 relations.  For width >= 3, collinear triples also exist in the
    full projective set, so weight 3 remains a conservative red flag.
    """
    if width <= 1:
        return 0
    return 3 if q > 2 else 3


def estimate_c4_surface(params: SableParams, *, block_size: int | None = None) -> C4SurfaceReport:
    ell = block_size or params.c2_block_size
    widths = _block_widths(params.N, ell)
    c4_entries = sum(projective_count(params.q, w) for w in widths)
    c2_entries = sum(params.q**w - 1 for w in widths)
    c4 = compare_c4(params, block_size=ell)
    sparse_rows = params.N * params.N
    clpn_rows = c4_entries * params.m_c
    row_diffs = sum(projective_count(params.q, w) * max(0, projective_count(params.q, w) - 1) // 2 for w in widths) * params.m_c
    # Any pair of CLPN ciphertext rows can be subtracted, but only algebraic basis relations combine messages to zero.
    relation_pairs = sum(math.comb(projective_count(params.q, w), 2) if projective_count(params.q, w) >= 2 else 0 for w in widths)
    min_rel = min((c4_min_relation_weight_screen(params.q, w) for w in widths if w > 1), default=0)
    instances = [
        LPNInstance(
            name="C5_sparse_LPN_expansion_key_rows",
            q=params.q,
            dimension=params.n,
            samples=sparse_rows,
            eta=params.eta,
            row_weight=params.k,
            comment="N GSW matrices times N rows; same sparse-LPN surface as previous versions",
        ),
        LPNInstance(
            name="C5_C4_projective_CLPN_rows",
            q=params.q,
            dimension=params.n_c,
            samples=clpn_rows,
            eta=params.eta_c,
            row_weight=None,
            comment="C4 projective basis entries times m_c dense CLPN rows",
        ),
    ]
    estimated = [estimate_instance(inst) for inst in instances]
    feasible = [x.best_feasible_log2_work for x in estimated if x.best_feasible_log2_work is not None]
    best = min(feasible) if feasible else None
    warning = (
        "Projective C4 reduces entries relative to C2/C3, but the public basis is overcomplete. "
        "Low-weight linear relations exist in full projective blocks of width >= 2, so relation-derived zero-message samples must be analyzed."
    )
    return C4SurfaceReport(
        params=asdict(params),
        block_size=ell,
        block_widths=widths,
        c4_projective_entries=c4_entries,
        c2_full_dictionary_entries=c2_entries,
        reduction_vs_c2=float(c4.c4_vs_c2_ratio),
        sparse_lpn_expansion_rows=sparse_rows,
        clpn_compaction_rows=clpn_rows,
        clpn_dimension=params.n_c,
        row_difference_surfaces=row_diffs,
        pair_relation_surfaces_upper_bound=relation_pairs,
        minimum_linear_relation_weight_screen=min_rel,
        relation_warning=warning,
        best_feasible_attack_screen_bits=best,
        lpn_instances=[instance_estimate_to_dict(x) for x in estimated],
        interpretation="diagnostic C5 screen only; not a certified cryptanalysis result",
    )


def format_surface_report(report: C4SurfaceReport) -> str:
    p = report.params
    lines = [
        f"C5 C4 surface screen for {p['name']}",
        f"q={p['q']} N={p['n'] + 1} block_size={report.block_size} widths={report.block_widths[:8]}{'...' if len(report.block_widths) > 8 else ''}",
        f"C4 projective entries={report.c4_projective_entries}",
        f"C2 full dictionary entries={report.c2_full_dictionary_entries}",
        f"C4/C2 entry ratio={report.reduction_vs_c2:.6g}",
        f"Sparse-LPN expansion rows={report.sparse_lpn_expansion_rows}",
        f"C4 CLPN rows={report.clpn_compaction_rows} dimension={report.clpn_dimension}",
        f"Row-difference surfaces={report.row_difference_surfaces}",
        f"Projective pair relation upper bound={report.pair_relation_surfaces_upper_bound}",
        f"Minimum linear relation weight screen={report.minimum_linear_relation_weight_screen}",
        f"Best feasible attack-screen bits={report.best_feasible_attack_screen_bits}",
        report.relation_warning,
    ]
    for inst in report.lpn_instances:
        lines.append("")
        lines.append(
            f"Instance {inst['instance']['name']}: status={inst['status']} best={inst['best_feasible_log2_work']}"
        )
        for w in inst["warnings"]:
            lines.append(f"  warning: {w}")
    return "\n".join(lines)

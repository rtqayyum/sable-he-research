"""Dedicated public-sample attack screening for C2 block dictionaries.

The earlier C2 estimator counted the dictionary as ``entries * m_c`` CLPN rows.
That is not enough.  A block dictionary publishes many CLPN ciphertexts whose
messages are related linear forms of the same secret block.  Even when messages
are hidden, public differences generate several LPN-like screening surfaces:

* within-entry differences: subtract two rows of the same CLPN ciphertext to
  eliminate the message, yielding noisy equations in the compaction secret r;
* cross-entry differences inside a block: subtract rows from two dictionary
  entries.  The message difference is <u-v, s_block>, yielding noisy equations
  in the joint secret (r, s_block);
* expansion-key rows: the original sparse-LPN GSW-style public material.

This module is intentionally conservative and transparent.  It is a screening
tool, not a certified sparse/q-ary-LPN estimator.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .attacks import INF, AttackLine, bkw_screen_bits, clean_subset_bits, format_bits, log2_comb, prange_isd_bits, sparse_row_entropy_bits
from .estimator_c2 import c2_block_widths, c2_compaction_terms_worst, c2_dictionary_entries
from .field import majority_failure_bound, qary_piling_up
from .params import PRESETS, SableParams


def _status(bits: float, target_bits: float) -> str:
    if bits == INF:
        return "not-applicable-or-above-screen"
    if bits < 0.5 * target_bits:
        return "critical"
    if bits < target_bits:
        return "below-target"
    if bits < 1.25 * target_bits:
        return "near-target"
    return "above-target"


def _comb2(x: int) -> int:
    return x * (x - 1) // 2 if x >= 2 else 0


@dataclass(frozen=True)
class C2PublicSampleProfile:
    q: int
    N: int
    block_size: int
    block_widths: tuple[int, ...]
    dictionary_entries: int
    public_clpn_rows: int
    within_entry_difference_rows: int
    cross_entry_difference_rows: int
    max_cross_joint_dimension: int
    expansion_key_rows: int
    expansion_sparse_row_entropy_bits: float
    difference_noise_rate: float
    dense_dictionary_field_elements: int
    seeded_dictionary_field_elements_proxy: int
    seeded_storage_reduction_factor_proxy: float


def c2_public_sample_profile(params: SableParams, *, block_size: int | None = None) -> C2PublicSampleProfile:
    ell = params.c2_block_size if block_size is None else block_size
    widths = tuple(c2_block_widths(params.N, ell))
    entries_by_block = [params.q**w - 1 for w in widths]
    dictionary_entries = sum(entries_by_block)
    public_rows = dictionary_entries * params.m_c
    within_rows = dictionary_entries * _comb2(params.m_c)
    cross_rows = sum(_comb2(entries) * params.m_c * params.m_c for entries in entries_by_block)
    diff_noise = qary_piling_up(params.q, params.eta_c, 2)
    dense = dictionary_entries * params.m_c * (params.n_c + 1)
    seeded = dictionary_entries * (params.m_c + 1)  # b vectors plus one seed proxy per entry
    factor = dense / max(1, seeded)
    return C2PublicSampleProfile(
        q=params.q,
        N=params.N,
        block_size=ell,
        block_widths=widths,
        dictionary_entries=dictionary_entries,
        public_clpn_rows=public_rows,
        within_entry_difference_rows=within_rows,
        cross_entry_difference_rows=cross_rows,
        max_cross_joint_dimension=params.n_c + max(widths),
        expansion_key_rows=params.N * params.N,
        expansion_sparse_row_entropy_bits=sparse_row_entropy_bits(params.n, params.k, params.q),
        difference_noise_rate=diff_noise,
        dense_dictionary_field_elements=dense,
        seeded_dictionary_field_elements_proxy=seeded,
        seeded_storage_reduction_factor_proxy=factor,
    )


def _line(name: str, target: str, bits: float, target_bits: float, details: str) -> AttackLine:
    return AttackLine(name=name, target=target, bits=bits, status=_status(bits, target_bits), details=details)


def c2_attack_lines(params: SableParams, *, block_size: int | None = None, target_bits: float = 128.0) -> list[AttackLine]:
    profile = c2_public_sample_profile(params, block_size=block_size)
    ell = profile.block_size
    lines: list[AttackLine] = []

    # Original expansion-key sparse-LPN surfaces.
    g_clean = clean_subset_bits(params.n, profile.expansion_key_rows, params.eta)
    lines.append(_line(
        "clean-subset linear solving",
        "GSW/sparse-LPN expansion-key row screen",
        g_clean,
        target_bits,
        f"{profile.expansion_key_rows} row-level objects, dimension {params.n}, eta={params.eta:g}.",
    ))
    g_prange = prange_isd_bits(profile.expansion_key_rows, params.n, params.eta)
    lines.append(_line(
        "Prange information-set decoding",
        "GSW/sparse-LPN expansion-key row screen",
        g_prange,
        target_bits,
        "First-order decoding estimate using the expansion-key row count.",
    ))
    g_bkw = bkw_screen_bits(params.n, params.q, params.eta)
    lines.append(_line(
        "BKW-style noisy-linear learning",
        "GSW/sparse-LPN expansion-key row screen",
        g_bkw,
        target_bits,
        "Coarse q-ary BKW screen; specialized sparse-LPN estimators remain required.",
    ))

    # C2 within-entry row differences eliminate the dictionary message.
    c_clean = clean_subset_bits(params.n_c, profile.within_entry_difference_rows, profile.difference_noise_rate)
    lines.append(_line(
        "within-entry clean-subset solving",
        "C2 CLPN dictionary, message-eliminating row differences",
        c_clean,
        target_bits,
        (
            f"{profile.within_entry_difference_rows} within-entry difference rows, "
            f"dimension {params.n_c}, eta_eff={profile.difference_noise_rate:g}."
        ),
    ))
    c_prange = prange_isd_bits(profile.within_entry_difference_rows, params.n_c, profile.difference_noise_rate)
    lines.append(_line(
        "within-entry Prange/ISD screen",
        "C2 CLPN dictionary, message-eliminating row differences",
        c_prange,
        target_bits,
        "Random-code decoding proxy on row-difference samples from each dictionary entry.",
    ))
    c_bkw = bkw_screen_bits(params.n_c, params.q, profile.difference_noise_rate)
    lines.append(_line(
        "within-entry BKW-style screen",
        "C2 CLPN dictionary, compaction secret r",
        c_bkw,
        target_bits,
        "Coarse BKW screen for the q-ary LPN compaction secret under difference noise.",
    ))

    # Cross-entry differences in the same block create joint-secret samples.
    joint_dim = profile.max_cross_joint_dimension
    x_clean = clean_subset_bits(joint_dim, profile.cross_entry_difference_rows, profile.difference_noise_rate)
    lines.append(_line(
        "cross-entry clean-subset solving",
        "C2 block dictionary, joint secret (r, s_block)",
        x_clean,
        target_bits,
        (
            f"{profile.cross_entry_difference_rows} cross-entry difference rows inside blocks, "
            f"joint dimension <= {joint_dim}, eta_eff={profile.difference_noise_rate:g}."
        ),
    ))
    x_prange = prange_isd_bits(profile.cross_entry_difference_rows, joint_dim, profile.difference_noise_rate)
    lines.append(_line(
        "cross-entry Prange/ISD screen",
        "C2 block dictionary, joint secret (r, s_block)",
        x_prange,
        target_bits,
        "First-order decoding proxy for relations induced by differences of dictionary entries in the same block.",
    ))
    x_bkw = bkw_screen_bits(joint_dim, params.q, profile.difference_noise_rate)
    lines.append(_line(
        "cross-entry BKW-style screen",
        "C2 block dictionary, joint secret (r, s_block)",
        x_bkw,
        target_bits,
        "Coarse BKW screen on the enlarged q-ary LPN instance with dimension n_c + block_size.",
    ))

    # Entropy/storage informational screens.
    collision_excess = math.log2(max(1, profile.expansion_key_rows)) - 0.5 * profile.expansion_sparse_row_entropy_bits
    lines.append(AttackLine(
        name="sparse-row collision entropy",
        target="expansion row-distribution sanity screen",
        bits=profile.expansion_sparse_row_entropy_bits,
        status="informational" if collision_excess < 0 else "collision-risk",
        details=(
            f"sparse row entropy {profile.expansion_sparse_row_entropy_bits:.2f} bits; "
            f"birthday excess log2(samples)-H/2={collision_excess:.2f}."
        ),
    ))
    lines.append(AttackLine(
        name="seeded-storage does not reduce samples",
        target="C2 seeded dictionary storage model",
        bits=profile.seeded_storage_reduction_factor_proxy,
        status="informational",
        details=(
            f"seeded A representation reduces dense dictionary storage by about "
            f"{profile.seeded_storage_reduction_factor_proxy:.2f}x in this proxy, but public b rows remain "
            f"{profile.public_clpn_rows}; attack screens are unchanged."
        ),
    ))
    return lines


def c2_attack_report(
    params: SableParams,
    *,
    block_size: int | None = None,
    depth: int = 1,
    additions: int = 1,
    target_bits: float = 128.0,
) -> dict[str, Any]:
    profile = c2_public_sample_profile(params, block_size=block_size)
    lines = c2_attack_lines(params, block_size=profile.block_size, target_bits=target_bits)
    finite = [line.bits for line in lines if line.bits != INF and line.status != "informational"]
    min_bits = min(finite) if finite else INF
    blockers = [asdict(line) for line in lines if line.status in {"critical", "below-target", "collision-risk"}]
    compaction_terms = c2_compaction_terms_worst(params.N, profile.block_size, params.N)
    eta_comp = qary_piling_up(params.q, params.eta_c, compaction_terms)
    # A simple replica-level qualitative flag, not a full evaluation-depth bound.
    majority_bound = majority_failure_bound(params.replicas, min(1.0, eta_comp))
    return {
        "params": asdict(params),
        "target_bits": target_bits,
        "depth": depth,
        "additions": additions,
        "profile": asdict(profile),
        "c2_dictionary_entries_formula": "sum_j(q^{ell_j}-1)",
        "within_entry_difference_rows_formula": "dictionary_entries * binom(m_c,2)",
        "cross_entry_difference_rows_formula": "sum_j binom(q^{ell_j}-1,2) * m_c^2",
        "worst_case_dense_row_compaction_terms": compaction_terms,
        "aggregate_compaction_noise_at_dense_row_terms": eta_comp,
        "majority_bound_from_compaction_noise_only": majority_bound,
        "minimum_screen_bits": min_bits,
        "passes_screen": bool(min_bits >= target_bits and not blockers),
        "attack_lines": [asdict(line) for line in lines],
        "blockers": blockers,
        "design_conclusion": (
            "Seeded C2 reduces storage/materialization cost only.  It does not reduce public-sample exposure. "
            "The cross-entry dictionary-difference surface should be treated as a mandatory cryptanalysis item."
        ),
        "disclaimer": (
            "Screening estimate only; not a certified sparse/q-ary-LPN security estimator or a proof of insecurity. "
            "It is designed to catch regimes that are obviously unsuitable before detailed cryptanalysis."
        ),
    }


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, float) and math.isinf(obj):
        return "inf"
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, tuple):
        return [_jsonable(v) for v in obj]
    return obj


def format_c2_attack_report(report: dict[str, Any]) -> str:
    p = report["params"]
    profile = report["profile"]
    lines: list[str] = []
    lines.append(f"Preset: {p['name']}  target={report['target_bits']} bits")
    lines.append(f"C2 block size: {profile['block_size']}  dictionary entries: {profile['dictionary_entries']}")
    lines.append(
        f"Public CLPN rows: {profile['public_clpn_rows']}  "
        f"within-entry diffs: {profile['within_entry_difference_rows']}  "
        f"cross-entry diffs: {profile['cross_entry_difference_rows']}"
    )
    lines.append(
        f"Seeded storage proxy: dense={profile['dense_dictionary_field_elements']} field elements, "
        f"seeded={profile['seeded_dictionary_field_elements_proxy']} field elements, "
        f"reduction={profile['seeded_storage_reduction_factor_proxy']:.2f}x"
    )
    lines.append(f"Minimum finite screen bits: {format_bits(report['minimum_screen_bits'])}")
    lines.append(f"Passes screening target: {report['passes_screen']}")
    lines.append("Attack screens:")
    for line in report["attack_lines"]:
        lines.append(
            f"  - {line['name']} [{line['target']}]: bits={format_bits(line['bits'])} status={line['status']}"
        )
        lines.append(f"    {line['details']}")
    if report["blockers"]:
        lines.append("Blockers:")
        for line in report["blockers"]:
            lines.append(f"  - {line['target']}: {line['name']} at {format_bits(line['bits'])} bits ({line['status']})")
    lines.append(report["design_conclusion"])
    lines.append(report["disclaimer"])
    return "\n".join(lines)


def write_report_files(report: dict[str, Any], out_txt: Path, out_json: Path | None = None) -> None:
    out_txt.write_text(format_c2_attack_report(report) + "\n")
    if out_json is not None:
        out_json.write_text(json.dumps(_jsonable(report), indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Dedicated C2 public-sample attack-surface screen")
    parser.add_argument("--preset", default="c2_toy_noisy", choices=sorted(PRESETS))
    parser.add_argument("--block-size", type=int, default=None)
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--additions", type=int, default=1)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = c2_attack_report(
        PRESETS[args.preset],
        block_size=args.block_size,
        depth=args.depth,
        additions=args.additions,
        target_bits=args.target_bits,
    )
    if args.json:
        print(json.dumps(_jsonable(report), indent=2))
    else:
        print(format_c2_attack_report(report))


if __name__ == "__main__":
    main()

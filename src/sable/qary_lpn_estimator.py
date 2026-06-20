"""Dedicated sparse/q-ary-LPN public-sample screening utilities.

These routines are conservative design screens.  They are not replacements for
state-of-the-art cryptanalysis.  They are included to make the C2/C3 public
sample surface explicit, especially when block dictionaries expose many CLPN
rows.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Any

from .attack import estimate_attack_surface
from .params import PRESETS


@dataclass(frozen=True)
class QaryBKWBlockScan:
    bits: float
    block_size: int
    levels: int
    table_bits: float
    detection_bits: float
    log2_required_samples: float
    finite_samples_available: bool

    def to_jsonable(self) -> dict[str, Any]:
        out = asdict(self)
        for key, value in list(out.items()):
            if isinstance(value, float) and math.isinf(value):
                out[key] = "inf"
        return out


def _json_float(x: float) -> float | str:
    if math.isinf(x):
        return "inf" if x > 0 else "-inf"
    if math.isnan(x):
        return "nan"
    return x


def qary_bkw_block_scan(n: int, q: int, eta: float, samples: int, *, max_block: int = 96) -> QaryBKWBlockScan:
    """Coarse q-ary BKW-style screen over block sizes.

    For block size b, the table side costs roughly q^b, so table_bits=b log2 q.
    The q-ary symmetric-noise bias is |1 - q eta/(q-1)|.  After many pairwise
    combinations, the distinguisher sample demand is represented by a simple
    bias^{-2^levels} proxy.  This is intentionally conservative and intended to
    reject obviously weak parameter surfaces, not to certify security.
    """
    if n <= 0 or q <= 1 or samples <= 0:
        raise ValueError("invalid q-ary LPN surface")
    if eta <= 0:
        return QaryBKWBlockScan(0.0, 1, n, math.log2(q), 0.0, math.log2(q), True)
    bias = abs(1.0 - (q * eta) / (q - 1.0))
    if bias <= 0.0:
        return QaryBKWBlockScan(float("inf"), 0, 0, float("inf"), float("inf"), float("inf"), False)
    log_bias = math.log2(bias)  # negative when 0<bias<1
    available_log = math.log2(samples)
    best: QaryBKWBlockScan | None = None
    for block in range(1, min(max_block, n) + 1):
        levels = math.ceil(n / block)
        table_bits = block * math.log2(q)
        if levels >= 63:
            detection_bits = float("inf")
        else:
            detection_bits = max(0.0, -2.0 * (2.0 ** levels) * log_bias)
        required_samples = max(table_bits, detection_bits)
        finite = required_samples <= available_log
        # If samples are insufficient, report attack work as table+distinguisher
        # but mark it as not enabled by the fixed public sample surface.
        bits = max(table_bits, detection_bits) + math.log2(levels + 1.0)
        cand = QaryBKWBlockScan(bits, block, levels, table_bits, detection_bits, required_samples, finite)
        if best is None or cand.bits < best.bits:
            best = cand
    assert best is not None
    return best


def estimate_qary_lpn_surface(
    *,
    name: str,
    n: int,
    q: int,
    eta: float,
    samples: int,
    row_weight: int | None = None,
    target_bits: float = 128.0,
) -> dict[str, Any]:
    base = estimate_attack_surface(name=name, n=n, q=q, eta=eta, samples=samples, row_weight=row_weight, target_bits=target_bits)
    bkw_q = qary_bkw_block_scan(n, q, eta, samples)
    sample_ratio = samples / max(1, n)
    clean_expectation = samples * ((1.0 - eta) if eta <= 1 else 0.0)
    warnings = list(base.warnings)
    if sample_ratio > 1000:
        warnings.append("very large public sample-to-dimension ratio; multi-sample LPN attacks require specialist review")
    if bkw_q.finite_samples_available and bkw_q.bits < target_bits:
        warnings.append(f"q-ary block-BKW screen below {target_bits:.0f} bits")
    if not bkw_q.finite_samples_available:
        warnings.append("q-ary block-BKW screen is sample-limited on this fixed public surface")
    conservative = base.conservative_min_bits
    if bkw_q.finite_samples_available:
        conservative = min(conservative, bkw_q.bits)
    return {
        "name": name,
        "n": n,
        "q": q,
        "eta": eta,
        "samples": samples,
        "row_weight": row_weight,
        "sample_to_dimension_ratio": sample_ratio,
        "expected_errors": eta * samples,
        "expected_clean_samples": clean_expectation,
        "base_surface": base.to_jsonable(),
        "qary_bkw_block_scan": bkw_q.to_jsonable(),
        "conservative_min_bits": _json_float(conservative),
        "passes_target_screen": bool(conservative >= target_bits),
        "warnings": warnings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Screen q-ary/sparse-LPN public sample surfaces")
    parser.add_argument("--preset", default="c2_design_smallq", choices=sorted(PRESETS))
    parser.add_argument("--surface", choices=["expansion", "compaction"], default="compaction")
    parser.add_argument("--samples", type=int, default=None, help="override public sample count")
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    p = PRESETS[args.preset]
    if args.surface == "expansion":
        samples = p.N * p.N if args.samples is None else args.samples
        report = estimate_qary_lpn_surface(name="expansion_key_sparse_lpn", n=p.n, q=p.q, eta=p.eta, samples=samples, row_weight=p.k, target_bits=args.target_bits)
    else:
        samples = p.N * p.m_c if args.samples is None else args.samples
        report = estimate_qary_lpn_surface(name="compaction_key_qary_lpn", n=p.n_c, q=p.q, eta=p.eta_c, samples=samples, row_weight=None, target_bits=args.target_bits)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Surface: {report['name']} q={report['q']} n={report['n']} samples={report['samples']} eta={report['eta']}")
        print(f"sample/dimension ratio: {report['sample_to_dimension_ratio']:.3g}")
        print(f"conservative min bits: {report['conservative_min_bits']} passes={report['passes_target_screen']}")
        bkw = report['qary_bkw_block_scan']
        print(f"q-ary BKW: bits={bkw['bits']} block={bkw['block_size']} levels={bkw['levels']} finite={bkw['finite_samples_available']}")
        if report['warnings']:
            print("Warnings:")
            for w in report['warnings']:
                print(f"  - {w}")


if __name__ == "__main__":
    main()

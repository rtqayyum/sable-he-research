"""Baseline cost proxies for comparing SABLE-HE against Boolean-FHE style costs.

No external FHE library is required.  The module produces circuit-level operation
counts and symbolic cost proxies that can later be replaced by measured
OpenFHE/TFHE numbers.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from .estimator import balanced_product_quality, estimate, fresh_quality
from .params import PRESETS, SableParams


@dataclass(frozen=True)
class CircuitProfile:
    name: str
    inputs: int
    additions: int
    multiplications: int
    multiplicative_depth: int
    tfhe_bootstrapped_gates: int
    notes: str


PROFILES: dict[str, CircuitProfile] = {
    "and2": CircuitProfile("and2", inputs=2, additions=0, multiplications=1, multiplicative_depth=1, tfhe_bootstrapped_gates=1, notes="AND(x,y)=xy"),
    "or2": CircuitProfile("or2", inputs=2, additions=2, multiplications=1, multiplicative_depth=1, tfhe_bootstrapped_gates=1, notes="OR(x,y)=x+y-xy"),
    "xor2_qary": CircuitProfile("xor2_qary", inputs=2, additions=2, multiplications=1, multiplicative_depth=1, tfhe_bootstrapped_gates=1, notes="XOR over {0,1} in F_q: x+y-2xy"),
    "degree2_dot16": CircuitProfile("degree2_dot16", inputs=32, additions=15, multiplications=16, multiplicative_depth=1, tfhe_bootstrapped_gates=16, notes="sum of 16 pairwise products"),
    "degree4_tree": CircuitProfile("degree4_tree", inputs=4, additions=0, multiplications=3, multiplicative_depth=2, tfhe_bootstrapped_gates=3, notes="x1*x2*x3*x4 by balanced tree"),
    "validity_check8": CircuitProfile("validity_check8", inputs=8, additions=12, multiplications=8, multiplicative_depth=2, tfhe_bootstrapped_gates=20, notes="small synthetic voting/validity check"),
}


@dataclass(frozen=True)
class BaselineComparison:
    params: dict
    profile: dict
    sable: dict
    tfhe_proxy: dict
    interpretation: str


def compare_profile(params: SableParams, profile: CircuitProfile) -> BaselineComparison:
    est = estimate(params, depth=profile.multiplicative_depth, additions=max(1, profile.additions))
    N = params.N
    fq = fresh_quality(params)
    qd = balanced_product_quality(params, profile.multiplicative_depth)
    # Sparse matrix multiplication proxy: each homomorphic multiplication touches about N*w_left*w_right.
    # For a profile, use the final-depth quality as a high-side proxy.
    sable_mul_proxy = profile.multiplications * N * max(1, fq.row_support) * max(1, qd.row_support)
    sable_add_proxy = profile.additions * N * max(1, qd.row_support)
    sable_total = sable_mul_proxy + sable_add_proxy
    tfhe_gate_proxy = profile.tfhe_bootstrapped_gates
    interpretation = (
        "SABLE cost is a sparse-field-operation proxy; TFHE cost is a bootstrapped-gate count. "
        "Use this to choose benchmark circuits, not to claim wall-clock superiority."
    )
    return BaselineComparison(
        params=est["params"],
        profile=asdict(profile),
        sable={
            "estimated_failure_bound": est["final_replica_failure_bound"],
            "fresh_row_support": fq.row_support,
            "final_row_support": qd.row_support,
            "sparse_field_mul_add_proxy": sable_total,
            "size_estimates": est["size_estimates"],
        },
        tfhe_proxy={
            "bootstrapped_gate_count": tfhe_gate_proxy,
            "note": "Replace this with measured TFHE/OpenFHE timings in the next validation stage.",
        },
        interpretation=interpretation,
    )


def format_comparison(comp: BaselineComparison) -> str:
    p = comp.params
    prof = comp.profile
    lines = [
        f"Baseline proxy: preset={p['name']} circuit={prof['name']}",
        f"Circuit: inputs={prof['inputs']} adds={prof['additions']} muls={prof['multiplications']} depth={prof['multiplicative_depth']}",
        f"Notes: {prof['notes']}",
        "SABLE proxy:",
        f"  final failure bound: {comp.sable['estimated_failure_bound']:.6g}",
        f"  row support fresh/final: {comp.sable['fresh_row_support']} / {comp.sable['final_row_support']}",
        f"  sparse field-operation proxy: {comp.sable['sparse_field_mul_add_proxy']}",
        "TFHE/FHEW-style proxy:",
        f"  bootstrapped gate count: {comp.tfhe_proxy['bootstrapped_gate_count']}",
        comp.interpretation,
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Symbolic baseline comparison for SABLE-HE circuits")
    parser.add_argument("--preset", default="toy_depth2", choices=sorted(PRESETS))
    parser.add_argument("--profile", default="degree4_tree", choices=sorted(PROFILES))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    comp = compare_profile(PRESETS[args.preset], PROFILES[args.profile])
    if args.json:
        print(json.dumps(asdict(comp), indent=2))
    else:
        print(format_comparison(comp))


if __name__ == "__main__":
    main()

"""Operation profiles and comparison proxies for SABLE-HE."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .c4_estimator import compare as compare_c4
from .estimator import estimate
from .params import SableParams


@dataclass(frozen=True)
class OperationSupport:
    operation: str
    native: bool
    sable_expression: str
    multiplicative_depth: int | str
    comments: str


SUPPORT_TABLE: list[OperationSupport] = [
    OperationSupport("constant", True, "gamma * I", 0, "public constants add no noise"),
    OperationSupport("addition", True, "C1 + C2", 0, "linear operation"),
    OperationSupport("subtraction", True, "C1 - C2", 0, "linear operation"),
    OperationSupport("negation", True, "-C", 0, "linear operation"),
    OperationSupport("scalar multiplication", True, "alpha * C", 0, "linear operation"),
    OperationSupport("multiplication", True, "C1 C2", 1, "main nonlinear operation; increases sparsity/noise"),
    OperationSupport("polynomial evaluation", True, "Horner or circuit DAG", "degree-dependent", "bounded by multiplicative depth"),
    OperationSupport("Boolean NOT", True, "1 - x", 0, "valid for plaintext bits"),
    OperationSupport("Boolean AND", True, "xy", 1, "valid for plaintext bits"),
    OperationSupport("Boolean OR", True, "x + y - xy", 1, "valid for plaintext bits"),
    OperationSupport("Boolean XOR", True, "x + y - 2xy", 1, "valid for plaintext bits in odd prime fields"),
    OperationSupport("equality to constant", False, "1 - (x-a)^(q-1)", "ceil(log(q-1))", "algebraically possible but too expensive for large q"),
    OperationSupport("field inverse", False, "x^(q-2)", "ceil(log(q-2))", "only for nonzero plaintexts; expensive"),
    OperationSupport("integer comparison/order", False, "bit decomposition or lookup", "not native", "requires a different encoding or TFHE/FHEW-style lookup/bootstrapping"),
    OperationSupport("division", False, "x * y^(q-2)", "expensive", "only field division by nonzero y; not native integer division"),
]


@dataclass(frozen=True)
class OperationProfile:
    name: str
    additions: int
    scalar_mults: int
    multiplications: int
    multiplicative_depth: int
    tfhe_boolean_gate_proxy: int | None
    bfv_bgv_additions: int
    bfv_bgv_multiplications: int
    ckks_relevance: str
    notes: str


PROFILES: dict[str, OperationProfile] = {
    "add": OperationProfile("add", 1, 0, 0, 0, None, 1, 0, "not needed for exact F_q", "linear addition"),
    "sub": OperationProfile("sub", 1, 1, 0, 0, None, 1, 0, "not needed for exact F_q", "addition with -1 scaling"),
    "scalar_mul": OperationProfile("scalar_mul", 0, 1, 0, 0, None, 0, 0, "not needed for exact F_q", "public scalar multiply"),
    "mul": OperationProfile("mul", 0, 0, 1, 1, None, 0, 1, "multiplication is supported approximately", "field multiplication"),
    "square": OperationProfile("square", 0, 0, 1, 1, None, 0, 1, "multiplication is supported approximately", "x^2"),
    "poly2": OperationProfile("poly2", 2, 1, 1, 1, None, 2, 1, "approximate polynomial possible", "x^2 + 3x + 5"),
    "poly3": OperationProfile("poly3", 3, 2, 2, 2, None, 3, 2, "approximate polynomial possible", "x^3 + 2x^2 + 3x + 4"),
    "bool_not": OperationProfile("bool_not", 1, 1, 0, 0, 0, 1, 0, "not a natural CKKS operation", "1-x"),
    "bool_and": OperationProfile("bool_and", 0, 0, 1, 1, 1, 0, 1, "not a natural CKKS operation", "xy"),
    "bool_or": OperationProfile("bool_or", 2, 0, 1, 1, 1, 2, 1, "not a natural CKKS operation", "x+y-xy"),
    "bool_xor": OperationProfile("bool_xor", 2, 1, 1, 1, 1, 2, 1, "not a natural CKKS operation", "x+y-2xy"),
    "quadratic4": OperationProfile("quadratic4", 3, 0, 4, 1, 7, 3, 4, "approximate quadratic possible", "sum of four pairwise products"),
}


def support_table_as_dicts() -> list[dict]:
    return [asdict(x) for x in SUPPORT_TABLE]


def compare_operation(params: SableParams, profile: OperationProfile, *, c4_block_size: int | None = None) -> dict:
    depth = max(0, profile.multiplicative_depth)
    additions_for_estimator = max(1, profile.additions + profile.scalar_mults + 1)
    est = estimate(params, depth=depth, additions=additions_for_estimator)
    c4 = compare_c4(params, block_size=c4_block_size or params.c2_block_size)
    size = est["size_estimates"]
    # Sparse operation proxy: matrix multiplication dominates, linear operations are row-sparse additions.
    final_entries = int(size["final_expanded_sparse_entries_capped"])
    mul_proxy = int(size["multiplication_cost_proxy"]) * max(0, profile.multiplications)
    lin_proxy = params.N * max(1, profile.additions + profile.scalar_mults) * max(1, int(est["evaluated_quality"]["row_support"]))
    return {
        "params": params.name,
        "operation": asdict(profile),
        "sable_c4": {
            "native_domain": "prime-field arithmetic F_q; Boolean via polynomial encodings on {0,1}",
            "estimated_failure_bound": est["final_replica_failure_bound"],
            "multiplicative_depth": depth,
            "expanded_sparse_entries_capped": final_entries,
            "sparse_field_operation_proxy": mul_proxy + lin_proxy,
            "mul_proxy_component": mul_proxy,
            "linear_proxy_component": lin_proxy,
            "c4_entries": c4.c4_entries,
            "c4_public_clpn_rows": c4.c4_public_clpn_rows,
            "c4_terms_bound": c4.terms_c4_bound,
        },
        "existing_method_proxies": {
            "TFHE_FHEW": {
                "gate_or_bootstrap_proxy": profile.tfhe_boolean_gate_proxy,
                "interpretation": "best fit for Boolean gates/comparisons/lookups; arithmetic integers decompose into many gates",
            },
            "BFV_BGV": {
                "ciphertext_additions": profile.bfv_bgv_additions,
                "ciphertext_multiplications": profile.bfv_bgv_multiplications,
                "interpretation": "best exact-arithmetic lattice baseline for modular integer/plaintext operations",
            },
            "CKKS": {
                "relevance": profile.ckks_relevance,
                "interpretation": "best for approximate real/complex arithmetic, not exact finite-field outputs",
            },
        },
        "warning": "proxy comparison only; not wall-clock superiority over OpenFHE, SEAL, or TFHE-rs",
    }


def compare_all(params: SableParams) -> list[dict]:
    return [compare_operation(params, profile) for profile in PROFILES.values()]


def dumps_table(params: SableParams) -> str:
    return json.dumps(compare_all(params), indent=2, sort_keys=True)

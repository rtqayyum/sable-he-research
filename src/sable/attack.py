"""Compatibility attack-screening shim for C2 estimators.

The validation repository contains several historical estimator modules.  This
shim supplies the small interface used by estimator_c2 while delegating the
actual message to transparent screening proxies.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from .attack_estimator import LPNInstance, estimate_instance
from .params import SableParams

DEFAULT_TARGET_BITS = 128.0


@dataclass(frozen=True)
class AttackSurface:
    name: str
    n: int
    q: int
    eta: float
    samples: int
    row_weight: int | None
    conservative_min_bits: float
    warnings: tuple[str, ...]

    def to_jsonable(self) -> dict[str, Any]:
        d = asdict(self)
        if math.isinf(d["conservative_min_bits"]):
            d["conservative_min_bits"] = "inf"
        return d


def correctness_noise_factor(k: int, depth: int, additions: int = 1) -> float:
    w = (k + 1) ** 2
    factor = float(k + 2)
    for _ in range(depth):
        factor *= 1.0 + w
        w *= w
        if factor > 1e300:
            return float("inf")
    return max(1, additions) * factor


def correctness_eta_ceiling(k: int, depth: int, additions: int = 1, target_eval_error: float = 0.10) -> float:
    factor = correctness_noise_factor(k, depth, additions)
    if factor <= 0 or math.isinf(factor):
        return 0.0
    return min(1.0, target_eval_error / factor)


def expansion_samples(params: SableParams) -> int:
    return params.N * params.N


def estimate_attack_surface(*, name: str, n: int, q: int, eta: float, samples: int, row_weight: int | None, target_bits: float = DEFAULT_TARGET_BITS) -> AttackSurface:
    inst = LPNInstance(name=name, q=q, dimension=n, samples=samples, eta=eta, row_weight=row_weight)
    est = estimate_instance(inst)
    best = est.best_feasible_log2_work if est.best_feasible_log2_work is not None else float("inf")
    warnings = tuple(est.warnings)
    return AttackSurface(name=name, n=n, q=q, eta=eta, samples=samples, row_weight=row_weight, conservative_min_bits=best, warnings=warnings)


def format_attack_summary(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Attack-screening verdict: {summary.get('verdict', 'screen')}  target={summary.get('target_bits', DEFAULT_TARGET_BITS)} bits")
    lines.append(f"Overall conservative min proxy: {summary.get('overall_min_attack_bits_proxy')}")
    for surf in summary.get("surfaces", []):
        lines.append("")
        lines.append(f"Surface: {surf.get('name')}")
        lines.append(f"  n={surf.get('n')} q={surf.get('q')} eta={surf.get('eta')} samples={surf.get('samples')}")
        lines.append(f"  conservative min bits: {surf.get('conservative_min_bits')}")
        if surf.get("warnings"):
            lines.append("  Warnings:")
            for warning in surf.get("warnings", []):
                lines.append(f"    - {warning}")
    trade = summary.get("correctness_security_tradeoff")
    if trade:
        lines.append("")
        lines.append("Correctness/security tradeoff:")
        lines.append(f"  depth={trade.get('depth')} additions={trade.get('additions')} eta_ceiling={trade.get('eta_ceiling_for_eval_error_0p10')}")
        if trade.get("note"):
            lines.append(f"  {trade['note']}")
    return "\n".join(lines)

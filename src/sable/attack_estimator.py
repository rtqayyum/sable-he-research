"""Screening attack-cost estimator for SABLE-HE parameter work.

This module is intentionally conservative and transparent.  It is not a
replacement for a dedicated sparse-LPN / q-ary-LPN cryptanalysis package.
The goal is to catch obviously bad parameter choices, quantify public-key
sample exposure, and produce repeatable tables for the research notebook.

Implemented screening models
----------------------------
* zero-noise linear solve warning;
* direct secret enumeration q^n;
* Prange-style information-set decoding cost for the LPN-as-decoding view;
* BKW-style block reduction proxy using binary-projection bias;
* sparse-row structural warnings for very small row weights.

The estimates are useful for comparing presets and for identifying bottlenecks.
They should not be quoted as certified security levels.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Iterable

from .params import PRESETS, SableParams

INF = float("inf")


@dataclass(frozen=True)
class LPNInstance:
    """Public noisy-linear-equation exposure to screen."""

    name: str
    q: int
    dimension: int
    samples: int
    eta: float
    row_weight: int | None = None
    comment: str = ""


@dataclass(frozen=True)
class AttackCost:
    name: str
    log2_work: float | None
    log2_memory: float | None
    feasible_with_available_samples: bool
    model: str
    notes: list[str]


@dataclass(frozen=True)
class InstanceEstimate:
    instance: LPNInstance
    attacks: list[AttackCost]
    best_feasible_log2_work: float | None
    status: str
    warnings: list[str]


def _finite_or_none(x: float) -> float | None:
    if math.isfinite(x):
        return x
    return None


def log2_binom(n: int, k: int) -> float:
    """Return log2(binomial(n,k)) using lgamma for large n."""
    if k < 0 or k > n:
        return -INF
    if k == 0 or k == n:
        return 0.0
    k = min(k, n - k)
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)


def entropy_binary(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


def clean_subset_linear_solve(inst: LPNInstance) -> AttackCost:
    """Low-noise clean-subset screen.

    If samples >= dimension and eta is small, a random subset of `dimension`
    equations is entirely noise-free with probability approximately
    (1-eta)^dimension.  Trying random subsets and solving the resulting linear
    systems is therefore a devastating attack in very-low-noise regimes.  This
    screen is intentionally simple and should be refined for sparse-row rank
    effects, but it catches the most important correctness/security tension.
    """
    if inst.samples < inst.dimension:
        return AttackCost(
            name="clean_subset_linear_solve",
            log2_work=None,
            log2_memory=None,
            feasible_with_available_samples=False,
            model="random clean subset of n equations",
            notes=["not enough equations to select a full clean system"],
        )
    if inst.eta <= 0.0:
        bits = 0.0
    elif inst.eta >= 1.0:
        bits = INF
    else:
        bits = -inst.dimension * math.log2(1.0 - inst.eta)
    poly = 3.0 * math.log2(max(2, inst.dimension))
    return AttackCost(
        name="clean_subset_linear_solve",
        log2_work=_finite_or_none(bits + poly) if math.isfinite(bits) else None,
        log2_memory=2.0 * math.log2(max(2, inst.dimension)),
        feasible_with_available_samples=math.isfinite(bits),
        model="expected trials 1/(1-eta)^n plus polynomial linear algebra",
        notes=[
            f"clean-subset trial exponent without linear-algebra overhead is {bits:.4g} bits" if math.isfinite(bits) else "clean-subset probability is zero",
            "dominant red flag when correctness forces eta to be tiny",
        ],
    )


def direct_secret_enumeration(inst: LPNInstance) -> AttackCost:
    bits = inst.dimension * math.log2(inst.q)
    return AttackCost(
        name="direct_secret_enumeration",
        log2_work=bits,
        log2_memory=0.0,
        feasible_with_available_samples=True,
        model="try all q^n secrets and score against samples",
        notes=["baseline upper bound on brute-force work"],
    )


def zero_noise_linear_solve(inst: LPNInstance) -> AttackCost | None:
    if inst.eta != 0.0:
        return None
    if inst.samples < inst.dimension:
        return AttackCost(
            name="zero_noise_linear_solve",
            log2_work=None,
            log2_memory=None,
            feasible_with_available_samples=False,
            model="linear algebra over F_q when there is no noise",
            notes=["eta is zero but there are fewer equations than unknowns"],
        )
    poly_bits = 3.0 * math.log2(max(2, inst.dimension)) + math.log2(max(2, inst.q))
    return AttackCost(
        name="zero_noise_linear_solve",
        log2_work=poly_bits,
        log2_memory=2.0 * math.log2(max(2, inst.dimension)),
        feasible_with_available_samples=True,
        model="Gaussian elimination over F_q",
        notes=["zero noise makes the instance algebraically solvable; toy-only"],
    )


def prange_isd(inst: LPNInstance) -> AttackCost:
    """Prange-style information-set decoding screen.

    View m LPN samples as a length-m random linear code of dimension n and
    search for an information set containing no error positions.  The success
    probability of one information set is C(m-t,n)/C(m,n), where t is the
    observed Hamming error weight.  This is a classical baseline, not a modern
    optimized ISD implementation.
    """
    m = inst.samples
    n = inst.dimension
    if m <= n:
        return AttackCost(
            name="prange_isd",
            log2_work=None,
            log2_memory=None,
            feasible_with_available_samples=False,
            model="information-set decoding baseline",
            notes=["not enough redundancy: samples <= dimension"],
        )
    if inst.eta <= 0.0:
        return AttackCost(
            name="prange_isd",
            log2_work=0.0,
            log2_memory=2.0 * math.log2(max(2, n)),
            feasible_with_available_samples=True,
            model="information-set decoding baseline",
            notes=["zero-error case collapses to linear algebra"],
        )
    t = int(math.ceil(inst.eta * m))
    t = max(1, min(t, m))
    if m - t < n:
        return AttackCost(
            name="prange_isd",
            log2_work=None,
            log2_memory=None,
            feasible_with_available_samples=False,
            model="information-set decoding baseline",
            notes=["expected number of clean positions is below dimension"],
        )
    log_trials = log2_binom(m, n) - log2_binom(m - t, n)
    poly = 3.0 * math.log2(max(2, n)) + math.log2(max(2, inst.q))
    return AttackCost(
        name="prange_isd",
        log2_work=max(0.0, log_trials + poly),
        log2_memory=2.0 * math.log2(max(2, n)),
        feasible_with_available_samples=True,
        model="Prange clean-information-set probability C(m-t,n)/C(m,n)",
        notes=[
            f"uses t=ceil(eta*m)={t} errors for m={m} samples",
            "modern ISD variants can be substantially faster; use as baseline only",
        ],
    )


def modern_isd_floor(inst: LPNInstance) -> AttackCost:
    """Very rough modern-ISD floor for binary random-code regimes.

    May-Meurer-Thomae style asymptotics are often quoted near 2^(0.054 n_code)
    for specific binary random decoding regimes.  This is not a valid formula
    for every q, rate, or weight.  We include it as a pessimistic red-flag floor:
    if this number is already small, the preset needs attention.
    """
    m = inst.samples
    bits = 0.054 * m
    notes = [
        "heuristic red-flag floor inspired by modern binary ISD asymptotics",
        "not a certified estimate for q-ary, sparse, low-noise, or non-random regimes",
    ]
    if inst.q != 2:
        notes.append("q != 2: interpret only as a rough screening number")
    return AttackCost(
        name="modern_isd_floor_screen",
        log2_work=bits,
        log2_memory=None,
        feasible_with_available_samples=True,
        model="screening-only floor: 0.054 * code length",
        notes=notes,
    )


def bkw_proxy(inst: LPNInstance, max_block: int = 128) -> AttackCost:
    """BKW-style block-reduction proxy.

    For binary LPN, combining samples squares the bias at each reduction level.
    For q-ary LPN we use a binary-projection style bias proxy and account for
    q^b bucket cost.  This is a screening model; a real BKW estimator must model
    sample amplification, coded-BKW/LF variants, q-ary reductions, memory and
    representation choices.
    """
    n = inst.dimension
    q = inst.q
    eta = inst.eta
    if eta <= 0.0:
        return AttackCost(
            name="bkw_proxy",
            log2_work=0.0,
            log2_memory=0.0,
            feasible_with_available_samples=True,
            model="BKW proxy",
            notes=["zero noise: BKW unnecessary; linear algebra applies"],
        )
    if eta >= 0.5:
        return AttackCost(
            name="bkw_proxy",
            log2_work=None,
            log2_memory=None,
            feasible_with_available_samples=False,
            model="BKW proxy",
            notes=["binary-projection bias is non-positive at eta >= 1/2"],
        )

    bias = max(1e-300, 1.0 - 2.0 * eta)
    neg_log2_bias = -math.log2(bias)
    available_log_samples = math.log2(max(1, inst.samples))
    best: tuple[float, float, int, int, float] | None = None

    for block in range(1, min(max_block, n) + 1):
        levels = math.ceil(n / block)
        if levels > 60:
            # 2^levels is astronomically large; skip to avoid overflow.
            continue
        combined = 2.0**levels
        log_bucket = block * math.log2(q)
        log_majority_samples = 2.0 * combined * neg_log2_bias
        log_required_samples = log_bucket + math.log2(max(1, levels)) + log_majority_samples
        log_work = max(log_bucket + math.log2(max(1, levels)), log_majority_samples)
        log_memory = log_bucket
        if best is None or log_work < best[0]:
            best = (log_work, log_memory, block, levels, log_required_samples)

    if best is None:
        return AttackCost(
            name="bkw_proxy",
            log2_work=None,
            log2_memory=None,
            feasible_with_available_samples=False,
            model="BKW proxy",
            notes=["no block size gave a finite screening estimate"],
        )

    log_work, log_memory, block, levels, log_required_samples = best
    feasible = available_log_samples + 1e-9 >= log_required_samples
    notes = [
        f"best block={block}, levels={levels}",
        f"available log2(samples)={available_log_samples:.2f}",
        f"screened required log2(samples)={log_required_samples:.2f}",
        "sample-limited means this particular BKW proxy is not directly enabled by the public samples",
    ]
    return AttackCost(
        name="bkw_proxy",
        log2_work=log_work,
        log2_memory=log_memory,
        feasible_with_available_samples=feasible,
        model="block BKW proxy with binary-projection bias",
        notes=notes,
    )


def sparse_row_warning(inst: LPNInstance) -> AttackCost | None:
    if inst.row_weight is None:
        return None
    k = inst.row_weight
    if k <= 0:
        return AttackCost(
            name="sparse_row_degenerate",
            log2_work=0.0,
            log2_memory=0.0,
            feasible_with_available_samples=True,
            model="structural sparse-row screen",
            notes=["row_weight=0 gives samples independent of the secret coordinates"],
        )
    avg_incidence = inst.samples * k / max(1, inst.dimension)
    if k == 1:
        work = math.log2(max(2, inst.samples * inst.q))
        return AttackCost(
            name="coordinate_averaging_warning",
            log2_work=work,
            log2_memory=math.log2(max(2, inst.dimension * inst.q)),
            feasible_with_available_samples=avg_incidence >= 3,
            model="k=1 samples isolate one secret coordinate up to noise",
            notes=[
                f"average samples per coordinate is {avg_incidence:.2f}",
                "k=1 should never be used outside clean algebra tests",
            ],
        )
    if k <= 3:
        work = math.log2(max(2, inst.samples)) + k * math.log2(max(2, inst.dimension))
        return AttackCost(
            name="low_weight_structural_warning",
            log2_work=work,
            log2_memory=math.log2(max(2, inst.samples)),
            feasible_with_available_samples=True,
            model="hypergraph/low-weight sparse-LPN structural screen",
            notes=[
                f"row_weight={k} is very small; sparse-LPN security normally requires careful asymptotic growth",
                f"average coordinate incidence is {avg_incidence:.2f}",
                "this is a red-flag screen, not a fully modeled attack",
            ],
        )
    return None


def estimate_instance(inst: LPNInstance) -> InstanceEstimate:
    attacks: list[AttackCost] = []
    z = zero_noise_linear_solve(inst)
    if z is not None:
        attacks.append(z)
    attacks.append(clean_subset_linear_solve(inst))
    s = sparse_row_warning(inst)
    if s is not None:
        attacks.append(s)
    attacks.extend([
        direct_secret_enumeration(inst),
        prange_isd(inst),
        modern_isd_floor(inst),
        bkw_proxy(inst),
    ])

    feasible_bits = [a.log2_work for a in attacks if a.feasible_with_available_samples and a.log2_work is not None]
    best = min(feasible_bits) if feasible_bits else None
    warnings: list[str] = []
    if inst.eta == 0.0:
        warnings.append("zero noise: no cryptographic hiding against linear algebra")
    if inst.samples >= inst.dimension:
        warnings.append("public/evaluation key exposes at least as many samples as the secret dimension")
    if inst.row_weight is not None and inst.row_weight <= 3:
        warnings.append("very small sparse row weight; use only for tests unless justified by a proof/estimator")
    if best is not None and best < 80:
        status = "toy/broken-screen"
    elif best is not None and best < 128:
        status = "below-128-bit-screen"
    elif best is not None and best < 192:
        status = "at-least-128-bit-screen"
    elif best is not None:
        status = "high-screening-margin"
    else:
        status = "inconclusive"
    return InstanceEstimate(inst, attacks, best, status, warnings)


def public_key_instances(params: SableParams) -> list[LPNInstance]:
    """Construct the main LPN-like sample exposures created by the SABLE keys."""
    N = params.N
    return [
        LPNInstance(
            name="sparse_lpn_expansion_key",
            q=params.q,
            dimension=params.n,
            samples=N * N,
            eta=params.eta,
            row_weight=params.k,
            comment="N GSW matrices with N rows each, screening as sparse-LPN samples",
        ),
        LPNInstance(
            name="code_lpn_compaction_key",
            q=params.q,
            dimension=params.n_c,
            samples=N * params.m_c,
            eta=params.eta_c,
            row_weight=None,
            comment="N CLPN ciphertexts, each with m_c dense q-ary LPN rows",
        ),
    ]


def estimate_params(params: SableParams) -> dict:
    instances = [estimate_instance(inst) for inst in public_key_instances(params)]
    best_values = [x.best_feasible_log2_work for x in instances if x.best_feasible_log2_work is not None]
    best_overall = min(best_values) if best_values else None
    return {
        "params": asdict(params),
        "screening_warning": "These are heuristic screening estimates, not certified security levels.",
        "best_overall_feasible_log2_work": best_overall,
        "instances": [instance_estimate_to_dict(x) for x in instances],
    }


def attack_to_dict(a: AttackCost) -> dict:
    return {
        "name": a.name,
        "log2_work": _finite_or_none(a.log2_work) if a.log2_work is not None else None,
        "log2_memory": _finite_or_none(a.log2_memory) if a.log2_memory is not None else None,
        "feasible_with_available_samples": a.feasible_with_available_samples,
        "model": a.model,
        "notes": a.notes,
    }


def instance_estimate_to_dict(e: InstanceEstimate) -> dict:
    return {
        "instance": asdict(e.instance),
        "best_feasible_log2_work": e.best_feasible_log2_work,
        "status": e.status,
        "warnings": e.warnings,
        "attacks": [attack_to_dict(a) for a in e.attacks],
    }


def format_bits(bits: float | None) -> str:
    if bits is None:
        return "n/a"
    if bits >= 10000:
        return f"{bits:.2e}"
    return f"{bits:.2f}"


def format_instance(e: InstanceEstimate) -> str:
    inst = e.instance
    lines = []
    lines.append(
        f"Instance: {inst.name}  q={inst.q} n={inst.dimension} samples={inst.samples} "
        f"eta={inst.eta:g} row_weight={inst.row_weight}"
    )
    if inst.comment:
        lines.append(f"  comment: {inst.comment}")
    lines.append(f"  best feasible screen: {format_bits(e.best_feasible_log2_work)} bits  status={e.status}")
    for w in e.warnings:
        lines.append(f"  warning: {w}")
    lines.append("  attacks:")
    for a in e.attacks:
        feas = "yes" if a.feasible_with_available_samples else "no"
        lines.append(
            f"    - {a.name}: work={format_bits(a.log2_work)} mem={format_bits(a.log2_memory)} feasible={feas}"
        )
        if a.notes:
            lines.append(f"      note: {a.notes[0]}")
    return "\n".join(lines)


def format_params_estimate(est: dict) -> str:
    p = est["params"]
    lines = [
        f"Preset: {p['name']}  q={p['q']} n={p['n']} k={p['k']} eta={p['eta']} n_c={p['n_c']} m_c={p['m_c']} eta_c={p['eta_c']}",
        f"Overall best feasible screen: {format_bits(est['best_overall_feasible_log2_work'])} bits",
        est["screening_warning"],
    ]
    for item in est["instances"]:
        inst = LPNInstance(**item["instance"])
        attacks = [AttackCost(**a) for a in item["attacks"]]
        e = InstanceEstimate(inst, attacks, item["best_feasible_log2_work"], item["status"], item["warnings"])
        lines.append("")
        lines.append(format_instance(e))
    return "\n".join(lines)


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Screen SABLE-HE presets against simple LPN attack-cost models")
    parser.add_argument("--preset", default="prototype_medium", choices=sorted(PRESETS))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    est = estimate_params(PRESETS[args.preset])
    if args.json:
        print(json.dumps(est, indent=2))
    else:
        print(format_params_estimate(est))


if __name__ == "__main__":
    main()

"""Heuristic attack-cost estimator for SABLE-HE parameters.

This module is deliberately conservative and transparent. It does not certify
security. It collects sanity checks that a cryptography reviewer will expect to
see before any concrete parameter set is proposed:

* exhaustive secret search;
* Prange-style information-set decoding (ISD) on noisy linear systems;
* error-support enumeration for very low noise;
* a simple BKW/LPN distinguisher scan;
* sparse-row sample-space and birthday-collision diagnostics;
* public evaluation-key sample counts.

The models here are first-pass research heuristics. They are useful for ruling
out bad parameter choices and for generating tables, but they are not a
replacement for dedicated sparse-LPN/q-ary-LPN cryptanalysis.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from typing import Iterable

from .params import PRESETS, SableParams

INF = float('inf')


def _finite(x: float) -> float | None:
    if math.isfinite(x):
        return float(x)
    return None


def log2_binom(n: int, k: int) -> float:
    """Return log2(binomial(n, k)) using log-gamma arithmetic."""
    if k < 0 or k > n:
        return -INF
    if k == 0 or k == n:
        return 0.0
    k = min(k, n - k)
    return (
        math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
    ) / math.log(2)


def log2_add(values: Iterable[float]) -> float:
    vals = [v for v in values if math.isfinite(v)]
    if not vals:
        return INF
    m = max(vals)
    return m + math.log2(sum(2.0 ** (v - m) for v in vals))


def qary_bias(q: int, eta: float) -> float:
    """Bias multiplier for q-ary symmetric noise."""
    if q <= 1:
        raise ValueError('q must be at least 2')
    return abs(1.0 - (q * eta) / (q - 1))


def qary_piling_up_prob(q: int, eta: float, terms_log2: float) -> float:
    """Nonzero rate after summing 2^terms_log2 independent q-ary errors.

    The exact formula is (q-1)/q * (1 - beta^T), where
    beta = 1 - q eta/(q-1) and T = 2^terms_log2. This helper avoids overflow
    for large T by switching to the saturation limit.
    """
    if eta <= 0:
        return 0.0
    if eta >= 1:
        return (q - 1) / q
    beta = abs(1.0 - (q * eta) / (q - 1))
    if beta <= 0:
        return (q - 1) / q
    log_beta = math.log(beta)
    if terms_log2 > 60:
        return (q - 1) / q
    T = 2.0 ** terms_log2
    val = math.exp(T * log_beta)
    return ((q - 1) / q) * (1.0 - val)


@dataclass(frozen=True)
class AttackEstimate:
    name: str
    target: str
    log2_time: float | None
    log2_memory: float | None
    log2_samples: float | None
    model: str
    caveat: str


@dataclass(frozen=True)
class LayerReport:
    layer: str
    dimension: int
    modulus: int
    samples: int
    noise_rate: float
    expected_errors: float
    estimates: list[AttackEstimate]
    min_log2_time: float | None
    limiting_attack: str | None
    warnings: list[str]


@dataclass(frozen=True)
class SecurityReport:
    params: dict
    depth: int
    additions: int
    public_sample_counts: dict
    sparse_row_space: dict
    layers: list[LayerReport]
    overall_min_log2_time: float | None
    overall_limiting_attack: str | None
    interpretation: str
    global_warnings: list[str]


def exhaustive_secret_attack(layer: str, n: int, q: int) -> AttackEstimate:
    return AttackEstimate(
        name='exhaustive_secret_search',
        target=layer,
        log2_time=n * math.log2(q),
        log2_memory=math.log2(max(1, n)),
        log2_samples=0.0,
        model='try all q^n secrets and test against samples',
        caveat='baseline only; ignores algebraic shortcuts and parallelization',
    )


def prange_isd_attack(layer: str, n: int, m: int, q: int, eta: float) -> AttackEstimate:
    """Prange-style clean-information-set estimate.

    Given m noisy equations in n unknowns and about t=eta*m corrupted rows,
    Prange tries random information sets of size n until one contains no error.
    Success probability is C(m-t,n)/C(m,n). Solving the selected system is
    represented by a small n^omega term.
    """
    if eta <= 0:
        return AttackEstimate(
            'prange_isd_clean_set', layer, 0.0, 0.0, 0.0,
            'zero-noise systems are solved directly',
            'noise rate is zero, so the cryptographic instance is invalid',
        )
    if m < n:
        return AttackEstimate(
            'prange_isd_clean_set', layer, INF, INF, math.log2(max(1, m)),
            'requires at least n independent equations',
            'not applicable when the public sample count is below dimension',
        )
    t = min(m - n, max(1, int(math.ceil(eta * m))))
    log_success = log2_binom(m - t, n) - log2_binom(m, n)
    log_trials = max(0.0, -log_success)
    omega = 2.8
    log_solve = omega * math.log2(max(2, n))
    return AttackEstimate(
        'prange_isd_clean_set',
        layer,
        log2_time=log_trials + log_solve,
        log2_memory=2.0 * math.log2(max(2, n)),
        log2_samples=math.log2(max(1, m)),
        model='C(m,n)/C(m-t,n) clean-set trials plus dense linear algebra',
        caveat='rough random-code model; sparse-row structure may change rank and success probabilities',
    )


def error_support_attack(layer: str, n: int, m: int, q: int, eta: float) -> AttackEstimate:
    """Enumerate the error support and values, intended for low-noise sanity."""
    if eta <= 0:
        return AttackEstimate(
            'low_noise_error_support_search', layer, 0.0, 0.0, 0.0,
            'zero noise gives a directly solvable linear system',
            'noise rate is zero, so the cryptographic instance is invalid',
        )
    t = max(1, int(math.ceil(eta * m)))
    t = min(t, m)
    log_support = log2_binom(m, t)
    log_values = t * math.log2(max(1, q - 1))
    log_solve = 2.8 * math.log2(max(2, n))
    return AttackEstimate(
        'low_noise_error_support_search',
        layer,
        log2_time=log_support + log_values + log_solve,
        log2_memory=math.log2(max(2, n * n)),
        log2_samples=math.log2(max(1, m)),
        model='enumerate error positions and q-ary nonzero values, then solve',
        caveat='very pessimistic/naive, but useful for detecting dangerously tiny expected error counts',
    )


def bkw_attack_scan(layer: str, n: int, q: int, eta: float, max_block: int = 64) -> AttackEstimate:
    """Simple BKW/LPN block-size scan.

    The model splits n coordinates into blocks of size b. Tables have about
    q^b entries. After a=ceil(n/b) elimination levels, one sample is a sum of
    roughly 2^a original noisy samples, so the distinguishing bias is
    beta^(2^a). Detection needs about 1/bias^2 reduced samples.
    """
    if eta <= 0:
        return AttackEstimate(
            'bkw_block_scan', layer, 0.0, 0.0, 0.0,
            'zero-noise systems are solved directly',
            'noise rate is zero, so the cryptographic instance is invalid',
        )
    beta = qary_bias(q, eta)
    if beta <= 0:
        return AttackEstimate(
            'bkw_block_scan', layer, INF, INF, INF,
            'bias is zero under the q-ary symmetric-noise model',
            'distinguisher is sample-starved in this simplified model',
        )
    best: tuple[float, float, float, int, int] | None = None
    max_b = min(max_block, max(1, n))
    log2_beta = math.log2(beta)
    for b in range(1, max_b + 1):
        levels = int(math.ceil(n / b))
        table_log = b * math.log2(q)
        # If levels is large, the final bias is astronomically small.
        if levels > 60:
            sample_log = INF
        else:
            sample_log = max(0.0, -2.0 * (2.0 ** levels) * log2_beta)
        time_log = log2_add([math.log2(max(1, levels)) + table_log, sample_log])
        memory_log = table_log
        if best is None or time_log < best[0]:
            best = (time_log, memory_log, sample_log, b, levels)
    if best is None:
        return AttackEstimate('bkw_block_scan', layer, INF, INF, INF, 'scan failed', 'internal estimator failure')
    time_log, memory_log, sample_log, b, levels = best
    return AttackEstimate(
        'bkw_block_scan',
        layer,
        log2_time=time_log,
        log2_memory=memory_log,
        log2_samples=sample_log,
        model=f'min over block size b={b}, levels={levels}; table q^b plus 1/bias^2 samples',
        caveat='coarse first-pass BKW model; ignores advanced coded-BKW and sparse-specific improvements',
    )


def sparse_row_diagnostics(params: SableParams, public_sparse_rows: int) -> dict:
    row_space_bits = log2_binom(params.n, params.k) + params.k * math.log2(max(1, params.q - 1))
    sample_bits = math.log2(max(1, public_sparse_rows))
    birthday_margin_bits = 0.5 * row_space_bits - sample_bits
    full_space_margin_bits = row_space_bits - sample_bits
    return {
        'row_space_log2': row_space_bits,
        'public_sparse_rows_log2': sample_bits,
        'birthday_margin_log2': birthday_margin_bits,
        'full_space_margin_log2': full_space_margin_bits,
        'public_sparse_rows': public_sparse_rows,
    }


def layer_report(layer: str, n: int, q: int, m: int, eta: float) -> LayerReport:
    estimates = [
        exhaustive_secret_attack(layer, n, q),
        prange_isd_attack(layer, n, m, q, eta),
        error_support_attack(layer, n, m, q, eta),
        bkw_attack_scan(layer, n, q, eta),
    ]
    finite = [e for e in estimates if e.log2_time is not None and math.isfinite(e.log2_time)]
    if finite:
        limiting = min(finite, key=lambda e: e.log2_time or INF)
        min_bits = limiting.log2_time
        limiting_name = limiting.name
    else:
        min_bits = None
        limiting_name = None
    warnings: list[str] = []
    expected_errors = eta * m
    if eta == 0:
        warnings.append('zero noise: algebra test only, no LPN security')
    if expected_errors < 4 and eta > 0:
        warnings.append('expected error count is very small; low-noise attacks and direct decoding deserve special scrutiny')
    if m < n:
        warnings.append('sample count below dimension for this layer; security/evaluation-key modeling is incomplete')
    if min_bits is not None and min_bits < 80:
        warnings.append('heuristic attack cost below 80 bits')
    elif min_bits is not None and min_bits < 128:
        warnings.append('heuristic attack cost below 128 bits')
    return LayerReport(
        layer=layer,
        dimension=n,
        modulus=q,
        samples=m,
        noise_rate=eta,
        expected_errors=expected_errors,
        estimates=estimates,
        min_log2_time=min_bits,
        limiting_attack=limiting_name,
        warnings=warnings,
    )


def estimate_security(params: SableParams, depth: int = 1, additions: int = 1, extra_ciphertexts: int = 0) -> SecurityReport:
    """Generate a heuristic attack-surface report for a parameter preset."""
    N = params.N
    # Public sparse-LPN rows. Each GSW encryption has N rows. The expansion key
    # contains N GSW encryptions. Extra compact ciphertexts add at most replicas
    # Regev rows each; this argument lets experiments stress-test many samples.
    expansion_gsw_rows = N * N
    fresh_regev_rows = max(0, extra_ciphertexts) * params.replicas
    public_sparse_rows = expansion_gsw_rows + fresh_regev_rows

    # Public CLPN rows in the compaction key: N encryptions, m_c noisy rows each.
    compaction_rows = N * params.m_c

    sparse_diag = sparse_row_diagnostics(params, public_sparse_rows)
    sparse_layer = layer_report('sparse_lpn_gsw_expansion', params.n, params.q, public_sparse_rows, params.eta)
    comp_layer = layer_report('qary_lpn_compaction', params.n_c, params.q, compaction_rows, params.eta_c)

    layers = [sparse_layer, comp_layer]
    finite_layers = [lr for lr in layers if lr.min_log2_time is not None and math.isfinite(lr.min_log2_time)]
    if finite_layers:
        limiting_layer = min(finite_layers, key=lambda lr: lr.min_log2_time or INF)
        overall_min = limiting_layer.min_log2_time
        overall_name = f'{limiting_layer.layer}:{limiting_layer.limiting_attack}'
    else:
        overall_min = None
        overall_name = None

    global_warnings: list[str] = []
    if sparse_diag['birthday_margin_log2'] < 20:
        global_warnings.append('sparse row sample space is close to birthday-collision range; increase n/k/q or seed rows carefully')
    if depth > 3:
        global_warnings.append('depth above 3 is outside the intended validation envelope for current sparse-growth bounds')
    if params.name.startswith('toy'):
        global_warnings.append('toy preset: not intended to provide cryptographic security')
    if overall_min is not None and overall_min < 128:
        global_warnings.append('overall heuristic attack cost is below 128 bits')

    if overall_min is None:
        interpretation = 'unbounded/incomplete in this heuristic model; do not treat as a security claim'
    elif overall_min < 80:
        interpretation = 'toy or weak by this heuristic model'
    elif overall_min < 128:
        interpretation = 'research prototype only; below common 128-bit target by this heuristic model'
    else:
        interpretation = 'passes this first-pass heuristic threshold, but still requires dedicated sparse-LPN/q-ary-LPN review'

    return SecurityReport(
        params=asdict(params),
        depth=depth,
        additions=additions,
        public_sample_counts={
            'expansion_gsw_rows': expansion_gsw_rows,
            'fresh_regev_rows_from_extra_ciphertexts': fresh_regev_rows,
            'total_public_sparse_lpn_rows': public_sparse_rows,
            'compaction_lpn_rows': compaction_rows,
        },
        sparse_row_space=sparse_diag,
        layers=layers,
        overall_min_log2_time=overall_min,
        overall_limiting_attack=overall_name,
        interpretation=interpretation,
        global_warnings=global_warnings,
    )


def _attack_to_json(a: AttackEstimate) -> dict:
    return {
        'name': a.name,
        'target': a.target,
        'log2_time': _finite(a.log2_time if a.log2_time is not None else INF),
        'log2_memory': _finite(a.log2_memory if a.log2_memory is not None else INF),
        'log2_samples': _finite(a.log2_samples if a.log2_samples is not None else INF),
        'model': a.model,
        'caveat': a.caveat,
    }


def report_to_jsonable(report: SecurityReport) -> dict:
    return {
        'params': report.params,
        'depth': report.depth,
        'additions': report.additions,
        'public_sample_counts': report.public_sample_counts,
        'sparse_row_space': report.sparse_row_space,
        'layers': [
            {
                'layer': layer.layer,
                'dimension': layer.dimension,
                'modulus': layer.modulus,
                'samples': layer.samples,
                'noise_rate': layer.noise_rate,
                'expected_errors': layer.expected_errors,
                'min_log2_time': _finite(layer.min_log2_time if layer.min_log2_time is not None else INF),
                'limiting_attack': layer.limiting_attack,
                'warnings': layer.warnings,
                'estimates': [_attack_to_json(a) for a in layer.estimates],
            }
            for layer in report.layers
        ],
        'overall_min_log2_time': _finite(report.overall_min_log2_time if report.overall_min_log2_time is not None else INF),
        'overall_limiting_attack': report.overall_limiting_attack,
        'interpretation': report.interpretation,
        'global_warnings': report.global_warnings,
    }


def format_security_report(report: SecurityReport) -> str:
    p = report.params
    lines: list[str] = []
    lines.append(f"Preset: {p['name']}  q={p['q']} n={p['n']} k={p['k']} n_c={p['n_c']} m_c={p['m_c']}")
    lines.append(f"Depth={report.depth} additions={report.additions}")
    lines.append('Public sample counts:')
    for k, v in report.public_sample_counts.items():
        lines.append(f'  {k}: {v}')
    lines.append('Sparse row-space diagnostics:')
    for k, v in report.sparse_row_space.items():
        if isinstance(v, float):
            lines.append(f'  {k}: {v:.3f}')
        else:
            lines.append(f'  {k}: {v}')
    for layer in report.layers:
        lines.append('')
        lines.append(f'Layer: {layer.layer}')
        lines.append(f'  dimension={layer.dimension} modulus={layer.modulus} samples={layer.samples} eta={layer.noise_rate:g}')
        lines.append(f'  expected_errors={layer.expected_errors:.6g}')
        if layer.min_log2_time is None:
            lines.append('  minimum attack cost: unavailable')
        else:
            lines.append(f'  minimum attack cost: 2^{layer.min_log2_time:.2f} via {layer.limiting_attack}')
        for est in layer.estimates:
            t = 'inf' if est.log2_time is None or not math.isfinite(est.log2_time) else f'{est.log2_time:.2f}'
            mem = 'inf' if est.log2_memory is None or not math.isfinite(est.log2_memory) else f'{est.log2_memory:.2f}'
            samp = 'inf' if est.log2_samples is None or not math.isfinite(est.log2_samples) else f'{est.log2_samples:.2f}'
            lines.append(f'    - {est.name}: time=2^{t}, memory=2^{mem}, samples=2^{samp}')
            lines.append(f'      model: {est.model}')
            lines.append(f'      caveat: {est.caveat}')
        for warning in layer.warnings:
            lines.append(f'  warning: {warning}')
    lines.append('')
    if report.overall_min_log2_time is None:
        lines.append('Overall minimum attack cost: unavailable')
    else:
        lines.append(f'Overall minimum attack cost: 2^{report.overall_min_log2_time:.2f} via {report.overall_limiting_attack}')
    lines.append(f'Interpretation: {report.interpretation}')
    if report.global_warnings:
        lines.append('Global warnings:')
        for warning in report.global_warnings:
            lines.append(f'  - {warning}')
    lines.append('This is a heuristic estimator, not a security proof or certification.')
    return '\n'.join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description='Heuristic SABLE-HE sparse-LPN/q-ary-LPN attack estimator')
    parser.add_argument('--preset', default='toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--depth', type=int, default=1)
    parser.add_argument('--additions', type=int, default=1)
    parser.add_argument('--extra-ciphertexts', type=int, default=0)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    report = estimate_security(PRESETS[args.preset], depth=args.depth, additions=args.additions, extra_ciphertexts=args.extra_ciphertexts)
    if args.json:
        print(json.dumps(report_to_jsonable(report), indent=2))
    else:
        print(format_security_report(report))


if __name__ == '__main__':
    main()

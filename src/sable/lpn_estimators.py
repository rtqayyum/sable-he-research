"""Phase 8 LPN/ISD/BKW estimator framework for SABLE-HE.

This module provides reproducible *screening* estimators for public SABLE-HE
attack surfaces.  It is intentionally conservative and transparent: it reports
which simple screens are finite, which are sample-limited, and which need
specialist review.  The outputs are suitable for parameter-package appendices
and external cryptanalysis requests, not certification.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .parameter_sets import candidate_names, evaluate_candidate

LOG2E = math.log2(math.e)


@dataclass(frozen=True)
class AttackSurface:
    """A noisy-linear-equation surface exposed by SABLE-HE."""

    name: str
    assumption: str
    n: int
    q: int
    eta: float
    samples: int
    row_weight: int | None = None
    priority: str = "normal"
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class EstimatorConfig:
    """Controls for the Phase 8 screening estimator."""

    target_bits: int = 128
    linear_algebra_exponent: float = 2.8
    max_bkw_levels: int = 18
    max_isd_p: int = 8
    include_quantum_sqrt_screen: bool = True


@dataclass(frozen=True)
class AttackEstimate:
    """One attack-family estimate for a surface."""

    family: str
    classical_bits: float
    quantum_sqrt_bits: float | None
    status: str
    notes: tuple[str, ...]
    parameters: dict[str, Any]


@dataclass(frozen=True)
class SurfaceEstimate:
    """All attack estimates for one public surface."""

    surface: AttackSurface
    estimates: tuple[AttackEstimate, ...]
    minimum_classical_bits: float
    minimum_quantum_sqrt_bits: float | None
    verdict: str
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class CandidateAttackReport:
    """Full attack-screening report for a candidate parameter set."""

    candidate: str
    version: str
    release_name: str
    target_bits: int
    surfaces: tuple[SurfaceEstimate, ...]
    global_minimum_classical_bits: float
    global_minimum_quantum_sqrt_bits: float | None
    verdict: str
    notes: tuple[str, ...]


def _safe_log2(x: float) -> float:
    if x <= 0:
        return float('-inf')
    return math.log2(x)


def _log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float('-inf')
    if k == 0 or k == n:
        return 0.0
    # lgamma is stable for large n and avoids enormous intermediate integers.
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def qary_piling_up(q: int, eta: float, terms: int) -> float:
    """Error probability after summing ``terms`` q-ary symmetric errors."""

    if terms <= 0:
        return 0.0
    if eta <= 0:
        return 0.0
    if eta >= (q - 1) / q:
        return (q - 1) / q
    return (q - 1) / q * (1.0 - (1.0 - q * eta / (q - 1)) ** terms)


def qary_bias(q: int, eta: float) -> float:
    """Absolute nontrivial-character bias of q-ary symmetric noise."""

    return abs(1.0 - q * eta / (q - 1))


def clean_subset_estimate(surface: AttackSurface, cfg: EstimatorConfig) -> AttackEstimate:
    """Screen for finding an error-free information subset by chance."""

    n = surface.n
    eta = min(max(surface.eta, 0.0), 1.0 - 1e-18)
    if surface.samples < n:
        return AttackEstimate(
            family='clean-subset',
            classical_bits=float('inf'),
            quantum_sqrt_bits=None,
            status='sample-limited',
            notes=('surface exposes fewer samples than the secret dimension',),
            parameters={'n': n, 'samples': surface.samples, 'eta': surface.eta},
        )
    if eta == 0.0:
        bits = 0.0
        status = 'reject-zero-noise'
        notes = ('zero noise makes the clean-subset screen trivial',)
    else:
        clean_probability_bits = -n * _safe_log2(1.0 - eta)
        lin_bits = cfg.linear_algebra_exponent * _safe_log2(max(n, 2))
        bits = clean_probability_bits + lin_bits
        status = 'finite'
        notes = ('proxy: wait for n clean equations then solve dense linear system',)
    return AttackEstimate(
        family='clean-subset',
        classical_bits=bits,
        quantum_sqrt_bits=bits / 2 if cfg.include_quantum_sqrt_screen else None,
        status=status,
        notes=notes,
        parameters={'n': n, 'eta': surface.eta, 'omega': cfg.linear_algebra_exponent},
    )


def prange_isd_estimate(surface: AttackSurface, cfg: EstimatorConfig) -> AttackEstimate:
    """Prange-style information-set decoding screen."""

    m = surface.samples
    n = surface.n
    if m < n:
        return AttackEstimate(
            family='prange-isd',
            classical_bits=float('inf'),
            quantum_sqrt_bits=None,
            status='sample-limited',
            notes=('surface exposes fewer samples than the secret dimension',),
            parameters={'m': m, 'n': n, 'eta': surface.eta},
        )
    expected_errors = min(max(int(round(surface.eta * m)), 0), max(m - n, 0))
    if expected_errors == 0:
        bits = cfg.linear_algebra_exponent * _safe_log2(max(n, 2))
        status = 'low-error-warning'
        notes = ('expected public errors below one; Prange proxy dominated by linear algebra',)
    else:
        numerator = _log2_comb(m, n)
        denominator = _log2_comb(max(m - expected_errors, 0), n)
        bits = max(0.0, numerator - denominator + cfg.linear_algebra_exponent * _safe_log2(max(n, 2)))
        status = 'finite'
        notes = ('proxy: probability that an information set avoids all errors',)
    return AttackEstimate(
        family='prange-isd',
        classical_bits=bits,
        quantum_sqrt_bits=bits / 2 if cfg.include_quantum_sqrt_screen else None,
        status=status,
        notes=notes,
        parameters={'m': m, 'n': n, 'expected_errors': expected_errors, 'omega': cfg.linear_algebra_exponent},
    )


def stern_like_isd_estimate(surface: AttackSurface, cfg: EstimatorConfig) -> AttackEstimate:
    """Coarse Stern/Dumer-style ISD screen.

    This is deliberately a screen, not a certified estimator.  It subtracts a
    collision/list gain from the Prange proxy and reports the best small split
    parameter found.  It is useful for flagging parameters that only pass Prange
    by a narrow margin.
    """

    prange = prange_isd_estimate(surface, cfg).classical_bits
    best_bits = prange
    best_p = 0
    best_l = 0
    n = max(surface.n, 2)
    m = max(surface.samples, n + 1)
    redundancy = max(m - n, 1)
    for p in range(1, cfg.max_isd_p + 1):
        for l in range(1, min(64, redundancy) + 1):
            list_gain = min(_log2_comb(n // 2, p), l + p * _safe_log2(max(surface.q - 1, 2)))
            collision_penalty = max(0.0, p * _safe_log2(max(n, 2)) - 0.5 * l)
            bits = max(0.0, prange - list_gain + collision_penalty)
            if bits < best_bits:
                best_bits = bits
                best_p = p
                best_l = l
    return AttackEstimate(
        family='stern-dumer-isd-screen',
        classical_bits=best_bits,
        quantum_sqrt_bits=best_bits / 2 if cfg.include_quantum_sqrt_screen else None,
        status='heuristic-screen',
        notes=('coarse list-decoding gain screen; not a replacement for specialized code-based estimators',),
        parameters={'best_p': best_p, 'best_l': best_l, 'baseline_prange_bits': prange},
    )


def bkw_estimate(surface: AttackSurface, cfg: EstimatorConfig) -> AttackEstimate:
    """Block-BKW-style distinguishing proxy for q-ary LPN."""

    beta = qary_bias(surface.q, surface.eta)
    if beta <= 0:
        return AttackEstimate(
            family='qary-block-bkw',
            classical_bits=float('inf'),
            quantum_sqrt_bits=None,
            status='zero-bias',
            notes=('noise is uniform at character level; this simple BKW distinguisher has no bias',),
            parameters={'bias': beta},
        )
    best_bits = float('inf')
    best_level = 0
    best_block = 0
    notes: list[str] = []
    for levels in range(1, cfg.max_bkw_levels + 1):
        block = max(1, math.ceil(surface.n / levels))
        table_bits = block * _safe_log2(max(surface.q, 2))
        combined_bias = beta ** (2 ** levels)
        if combined_bias <= 0:
            continue
        distinguisher_samples_bits = max(0.0, -2.0 * _safe_log2(combined_bias))
        available_samples_bits = _safe_log2(max(surface.samples, 1))
        sample_shortfall = max(0.0, distinguisher_samples_bits - available_samples_bits)
        bits = table_bits + _safe_log2(max(levels, 1)) + sample_shortfall
        if bits < best_bits:
            best_bits = bits
            best_level = levels
            best_block = block
    if best_bits == float('inf'):
        status = 'unestimated'
        best_bits = 0.0
        notes.append('BKW proxy could not produce a finite table/distinguisher estimate')
    else:
        status = 'sample-aware-proxy'
        notes.append('proxy combines table cost and bias-driven sample shortfall')
        if surface.samples < surface.n:
            notes.append('public sample count is below secret dimension')
    return AttackEstimate(
        family='qary-block-bkw',
        classical_bits=best_bits,
        quantum_sqrt_bits=best_bits / 2 if cfg.include_quantum_sqrt_screen else None,
        status=status,
        notes=tuple(notes),
        parameters={'bias': beta, 'best_levels': best_level, 'best_block_width': best_block},
    )


def low_noise_warning(surface: AttackSurface, cfg: EstimatorConfig) -> AttackEstimate:
    """Low-noise warning screen used for reviewer triage."""

    expected_errors = surface.samples * surface.eta
    if expected_errors < 1:
        bits = cfg.linear_algebra_exponent * _safe_log2(max(surface.n, 2))
        status = 'critical-low-noise'
        notes = ('expected total errors below one over the public surface',)
    elif surface.eta < 2 ** -20:
        bits = -_safe_log2(surface.eta)
        status = 'warning-low-noise'
        notes = ('noise rate below 2^-20; specialist low-noise LPN review required',)
    else:
        bits = cfg.target_bits + 32.0
        status = 'not-triggered'
        notes = ('low-noise screen did not trigger',)
    return AttackEstimate(
        family='low-noise-screen',
        classical_bits=bits,
        quantum_sqrt_bits=bits / 2 if cfg.include_quantum_sqrt_screen and status != 'not-triggered' else None,
        status=status,
        notes=notes,
        parameters={'expected_errors': expected_errors, 'eta': surface.eta, 'samples': surface.samples},
    )


def estimate_surface(surface: AttackSurface, cfg: EstimatorConfig | None = None) -> SurfaceEstimate:
    cfg = cfg or EstimatorConfig()
    estimates = (
        clean_subset_estimate(surface, cfg),
        prange_isd_estimate(surface, cfg),
        stern_like_isd_estimate(surface, cfg),
        bkw_estimate(surface, cfg),
        low_noise_warning(surface, cfg),
    )
    finite = [e.classical_bits for e in estimates if math.isfinite(e.classical_bits)]
    min_classical = min(finite) if finite else float('inf')
    quantum_values = [e.quantum_sqrt_bits for e in estimates if e.quantum_sqrt_bits is not None and math.isfinite(e.quantum_sqrt_bits)]
    min_quantum = min(quantum_values) if quantum_values else None
    blockers = []
    if min_classical < cfg.target_bits:
        blockers.append(f'minimum classical screen below target: {min_classical:.2f} < {cfg.target_bits}')
    if min_quantum is not None and min_quantum < cfg.target_bits / 2:
        blockers.append(f'quantum-sqrt screen below half-target: {min_quantum:.2f}')
    if surface.samples >= surface.n:
        blockers.append('public sample count is at least the secret dimension')
    if surface.samples >= 1000 * max(surface.n, 1):
        blockers.append('large public sample-to-dimension ratio; specialist multi-sample review required')
    for e in estimates:
        if 'critical' in e.status:
            blockers.append(f'{e.family}: {e.status}')
    verdict = 'passes-internal-screens-only' if not blockers else 'requires-external-review'
    return SurfaceEstimate(surface, estimates, min_classical, min_quantum, verdict, tuple(blockers))


def surfaces_from_candidate(candidate: str, fl_clients: int = 100, model_length: int = 100) -> tuple[AttackSurface, ...]:
    report = evaluate_candidate(candidate)
    p = report.get('parameters') or report.get('candidate') or report.get('computed')
    q = int(p['q']); n = int(p['n']); k = int(p['k'])
    eta = float(p['eta']); n_c = int(p['n_c']); m_c = int(p['m_c']); eta_c = float(p['eta_c'])
    N = n + 1
    surfaces: list[AttackSurface] = []
    surfaces.append(AttackSurface(
        name='expansion_key_sparse_lpn_rows', assumption='sparse q-ary LPN', n=n, q=q, eta=eta,
        samples=N * N, row_weight=k + 1, priority='critical',
        notes=('GSW expansion key rows under independent secret s',),
    ))
    surfaces.append(AttackSurface(
        name='compaction_key_qary_lpn_rows', assumption='dense q-ary LPN / code decoding', n=n_c, q=q, eta=eta_c,
        samples=N * m_c, row_weight=None, priority='critical',
        notes=('coordinate compaction key rows under independent secret r',),
    ))
    surfaces.append(AttackSurface(
        name='same_entry_compaction_row_differences', assumption='derived q-ary LPN row differences', n=n_c, q=q,
        eta=qary_piling_up(q, eta_c, 2), samples=N * (m_c * max(m_c - 1, 0) // 2), row_weight=None, priority='critical',
        notes=('same-entry row differences cancel the repeated codeword message',),
    ))
    surfaces.append(AttackSurface(
        name='fl_input_ciphertext_sparse_lpn_rows', assumption='sparse q-ary LPN deployment surface', n=n, q=q, eta=eta,
        samples=max(0, fl_clients * model_length), row_weight=k + 1, priority='high',
        notes=(f'input ciphertext rows for fl_clients={fl_clients}, model_length={model_length}',),
    ))
    return tuple(surfaces)


def estimate_candidate(candidate: str, target_bits: int = 128, fl_clients: int = 100, model_length: int = 100) -> CandidateAttackReport:
    cfg = EstimatorConfig(target_bits=target_bits)
    estimates = tuple(estimate_surface(surface, cfg) for surface in surfaces_from_candidate(candidate, fl_clients, model_length))
    finite_classical = [s.minimum_classical_bits for s in estimates if math.isfinite(s.minimum_classical_bits)]
    global_classical = min(finite_classical) if finite_classical else float('inf')
    finite_quantum = [s.minimum_quantum_sqrt_bits for s in estimates if s.minimum_quantum_sqrt_bits is not None and math.isfinite(s.minimum_quantum_sqrt_bits)]
    global_quantum = min(finite_quantum) if finite_quantum else None
    notes = [
        'Phase 8 reports screening estimates only; outputs are not certified security estimates.',
        'All candidate rows require independent sparse-LPN, q-ary-LPN, ISD, and BKW review.',
    ]
    blockers = [b for s in estimates for b in s.blockers]
    verdict = 'passes-internal-screens-only' if not blockers else 'requires-external-review'
    return CandidateAttackReport(candidate, '0.9.0', 'Phase 8 LPN/ISD/BKW estimator framework', target_bits, estimates, global_classical, global_quantum, verdict, tuple(notes))


def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, '__dataclass_fields__'):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, tuple):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, list):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, float) and math.isinf(obj):
        return 'infinity'
    return obj


def estimator_info() -> dict[str, Any]:
    return {
        'version': '0.9.0',
        'release_name': 'Phase 8 LPN/ISD/BKW estimator framework',
        'status': 'internal strengthened estimator; not expert external cryptanalysis',
        'families': ['clean-subset', 'Prange/ISD', 'Stern-Dumer screen', 'q-ary block-BKW', 'low-noise screen'],
        'non_goals': ['certified security estimates', 'replacement for specialist LPN/ISD cryptanalysis', 'production parameter approval'],
        'candidate_inputs': candidate_names(),
    }


def format_surface(surface: SurfaceEstimate) -> str:
    lines = []
    s = surface.surface
    lines.append(f'{s.name}: assumption={s.assumption} n={s.n} q={s.q} eta={s.eta:g} samples={s.samples} priority={s.priority}')
    lines.append(f'  verdict={surface.verdict} min_classical={surface.minimum_classical_bits:.2f} bits')
    if surface.minimum_quantum_sqrt_bits is not None:
        lines.append(f'  min_quantum_sqrt={surface.minimum_quantum_sqrt_bits:.2f} bits')
    for e in surface.estimates:
        qbits = '' if e.quantum_sqrt_bits is None else f' quantum~{e.quantum_sqrt_bits:.2f}'
        lines.append(f'  - {e.family}: {e.classical_bits:.2f} bits{qbits} [{e.status}]')
    for blocker in surface.blockers:
        lines.append(f'    blocker: {blocker}')
    return '\n'.join(lines)


def format_candidate_report(report: CandidateAttackReport) -> str:
    lines = [
        f'SABLE-HE Phase 8 LPN/ISD/BKW report {report.version} ({report.release_name})',
        f'candidate={report.candidate} target={report.target_bits} verdict={report.verdict}',
        f'global_min_classical={report.global_minimum_classical_bits:.2f} bits',
    ]
    if report.global_minimum_quantum_sqrt_bits is not None:
        lines.append(f'global_min_quantum_sqrt={report.global_minimum_quantum_sqrt_bits:.2f} bits')
    lines.append('Surfaces:')
    for surface in report.surfaces:
        lines.append(format_surface(surface))
    lines.append('Notes:')
    for note in report.notes:
        lines.append(f'  - {note}')
    return '\n'.join(lines)


def write_estimator_package(output: str | Path, candidates: Iterable[str] | None = None, target_bits: int = 128) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    selected = list(candidates) if candidates else list(candidate_names())
    reports = [estimate_candidate(name, target_bits=target_bits) for name in selected]
    manifest = {
        'package': 'sable-he-research',
        'phase': 'phase8-lpn-isd-bkw-estimator',
        'version': '0.9.0',
        'target_bits': target_bits,
        'candidates': selected,
        'files': [],
    }
    (out / 'README.md').write_text(
        '# SABLE-HE Phase 8 estimator package\n\n'
        'This package contains reproducible internal screening estimates for SABLE-HE candidate parameters.\n'
        'It is not an expert external cryptanalysis report and does not certify parameters.\n',
        encoding='utf-8',
    )
    manifest['files'].append('README.md')
    rows = []
    for rep in reports:
        base = rep.candidate
        (out / f'{base}_attack_report.json').write_text(json.dumps(to_jsonable(rep), indent=2) + '\n', encoding='utf-8')
        (out / f'{base}_attack_report.md').write_text('```text\n' + format_candidate_report(rep) + '\n```\n', encoding='utf-8')
        manifest['files'].extend([f'{base}_attack_report.json', f'{base}_attack_report.md'])
        for surface in rep.surfaces:
            rows.append({
                'candidate': rep.candidate,
                'surface': surface.surface.name,
                'assumption': surface.surface.assumption,
                'n': surface.surface.n,
                'q': surface.surface.q,
                'eta': surface.surface.eta,
                'samples': surface.surface.samples,
                'min_classical_bits': surface.minimum_classical_bits,
                'verdict': surface.verdict,
            })
    with (out / 'surface_summary.csv').open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ['candidate'])
        writer.writeheader(); writer.writerows(rows)
    manifest['files'].append('surface_summary.csv')
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    manifest['files'].append('manifest.json')
    return manifest

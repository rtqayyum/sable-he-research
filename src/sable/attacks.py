
"""Screening attack-cost estimates for SABLE-HE parameters.

This module is intentionally conservative and transparent.  It is not a
certified LPN/sparse-LPN security estimator.  Its purpose is to catch
obviously unsafe regimes before implementation effort is spent on them.

The most important check is the low-noise / clean-subset screen.  If an
attacker has many noisy linear equations and the noise rate is very small,
a random set of `dimension` equations is clean with probability roughly
`(1-eta)**dimension`.  Repeating linear solving on random subsets then costs
about `dimension * -log2(1-eta)` bits, ignoring polynomial factors.  This is
a standard sanity check for LPN-like designs and is often the first thing to
fail when correctness forces eta to be too small.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass

from .field import qary_piling_up
from .params import PRESETS, SableParams


INF = float('inf')


@dataclass(frozen=True)
class AttackLine:
    """One attack or sanity-check line in the security screen."""

    name: str
    target: str
    bits: float
    status: str
    details: str


@dataclass(frozen=True)
class SampleProfile:
    """Approximate public-sample profile exposed by the evaluation keys."""

    gsw_rows: int
    gsw_secret_dimension: int
    gsw_noise_rate: float
    clpn_difference_rows: int
    clpn_secret_dimension: int
    clpn_difference_noise_rate: float
    sparse_row_entropy_bits: float


def _safe_log2(x: float) -> float:
    if x <= 0:
        return -INF
    return math.log2(x)


def log2_comb(n: int, k: int) -> float:
    """Return log2(binomial(n, k)) using lgamma for large values."""
    if k < 0 or k > n:
        return -INF
    if k == 0 or k == n:
        return 0.0
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)


def sparse_row_entropy_bits(n: int, k: int, q: int) -> float:
    """Entropy of a k-sparse row sampled by choosing support and nonzero values."""
    if k == 0:
        return 0.0
    return log2_comb(n, k) + k * math.log2(q - 1)


def sample_profile(params: SableParams) -> SampleProfile:
    """Approximate sample counts induced by public evaluation keys.

    Expansion key: N encryptions, each with N GSW rows, so N^2 row-level
    objects are exposed.  These are not plain known-message LPN samples, so
    this count is used as a conservative screening proxy rather than as a
    complete attack model.

    Compaction key: N CLPN ciphertexts, each with m_c repeated rows.  Since
    each ciphertext hides an unknown shift x_i * 1, row differences inside a
    CLPN ciphertext eliminate the shift and yield LPN-style samples with
    noise equal to the difference of two q-ary symmetric errors.
    """
    N = params.N
    gsw_rows = N * N
    clpn_difference_rows = N * (params.m_c * (params.m_c - 1) // 2)
    clpn_difference_noise = qary_piling_up(params.q, params.eta_c, 2)
    return SampleProfile(
        gsw_rows=gsw_rows,
        gsw_secret_dimension=params.n,
        gsw_noise_rate=params.eta,
        clpn_difference_rows=clpn_difference_rows,
        clpn_secret_dimension=params.n_c,
        clpn_difference_noise_rate=clpn_difference_noise,
        sparse_row_entropy_bits=sparse_row_entropy_bits(params.n, params.k, params.q),
    )


def clean_subset_bits(dimension: int, samples: int, eta: float) -> float:
    """Random clean-information-set screen for low-noise LPN.

    If samples >= dimension, choosing `dimension` samples at random is clean
    with probability about (1-eta)^dimension.  The expected number of random
    linear solves is the reciprocal of this probability.  We return the
    base-2 logarithm of that trial count.  This deliberately ignores
    polynomial Gaussian-elimination cost because the objective is to detect
    catastrophic low-noise settings.
    """
    if samples < dimension:
        return INF
    if eta <= 0:
        return 0.0
    if eta >= 1:
        return INF
    return -dimension * math.log2(1.0 - eta)


def prange_isd_bits(length: int, dimension: int, eta: float) -> float:
    """Very rough Prange/ISD work factor for random-code decoding.

    Treat the LPN problem as decoding a random linear code of length
    `length`, dimension `dimension`, and Hamming error weight round(eta*length).
    Prange succeeds when the selected information set contains no error.
    The returned value is log2(C(length, dimension)/C(length-t, dimension)).

    This is only a first-order binary-style screening estimate; modern ISD
    variants and q-ary refinements require dedicated external estimators.
    """
    if length < dimension:
        return INF
    if eta <= 0:
        return 0.0
    if eta >= 1:
        return INF
    t = int(round(eta * length))
    if t <= 0:
        return 0.0
    if length - t < dimension:
        return INF
    return max(0.0, log2_comb(length, dimension) - log2_comb(length - t, dimension))


def bkw_screen_bits(dimension: int, q: int, eta: float, max_block: int = 24) -> float:
    """Coarse BKW-style screening estimate.

    For each block size b, combine roughly 2^ceil(n/b) samples in the final
    reduced equation.  q-ary symmetric noise has residual bias
    base^(2^levels), where base = 1 - q*eta/(q-1).  The sample term is about
    bias^{-2}; the table term is about q^b.  We minimize the max of these
    two log-costs.

    This is not a replacement for a real BKW estimator.  It is included to
    make parameter sweeps sensitive to the classic BKW attack family.
    """
    if eta <= 0:
        return 0.0
    if eta >= (q - 1) / q:
        return INF
    base = abs(1.0 - (q * eta) / (q - 1))
    if base <= 0:
        return INF
    best = INF
    limit = max(1, min(max_block, dimension))
    for b in range(1, limit + 1):
        levels = math.ceil(dimension / b)
        # Avoid enormous integer construction when levels is large.
        if levels > 60:
            sample_bits = INF
        else:
            combined_terms = 2 ** levels
            bias_log2 = combined_terms * math.log2(base)
            sample_bits = max(0.0, -2.0 * bias_log2)
        table_bits = b * math.log2(q) + math.log2(max(1, levels))
        best = min(best, max(table_bits, sample_bits))
    return best


def _status(bits: float, target_bits: int) -> str:
    if bits == INF:
        return 'not-applicable-or-above-screen'
    if bits < 0.5 * target_bits:
        return 'critical'
    if bits < target_bits:
        return 'below-target'
    if bits < 1.25 * target_bits:
        return 'near-target'
    return 'above-target'


def attack_lines(params: SableParams, target_bits: int = 128) -> list[AttackLine]:
    profile = sample_profile(params)
    lines: list[AttackLine] = []

    g_clean = clean_subset_bits(profile.gsw_secret_dimension, profile.gsw_rows, profile.gsw_noise_rate)
    lines.append(AttackLine(
        name='clean-subset linear solving',
        target='GSW/sparse-LPN expansion-key screen',
        bits=g_clean,
        status=_status(g_clean, target_bits),
        details=(
            f'{profile.gsw_rows} row-level objects, dimension {profile.gsw_secret_dimension}, '
            f'eta={profile.gsw_noise_rate:g}; low eta makes random clean systems likely.'
        ),
    ))

    g_prange = prange_isd_bits(profile.gsw_rows, profile.gsw_secret_dimension, profile.gsw_noise_rate)
    lines.append(AttackLine(
        name='Prange information-set decoding',
        target='GSW/sparse-LPN expansion-key screen',
        bits=g_prange,
        status=_status(g_prange, target_bits),
        details='First-order random-code decoding estimate using expansion-key row count.',
    ))

    g_bkw = bkw_screen_bits(profile.gsw_secret_dimension, params.q, profile.gsw_noise_rate)
    lines.append(AttackLine(
        name='BKW-style parity/noisy-linear learning',
        target='GSW/sparse-LPN expansion-key screen',
        bits=g_bkw,
        status=_status(g_bkw, target_bits),
        details='Coarse q-ary BKW screen; use a specialized estimator before claiming security.',
    ))

    c_clean = clean_subset_bits(
        profile.clpn_secret_dimension,
        profile.clpn_difference_rows,
        profile.clpn_difference_noise_rate,
    )
    lines.append(AttackLine(
        name='clean-subset linear solving',
        target='CLPN compaction-key row-difference screen',
        bits=c_clean,
        status=_status(c_clean, target_bits),
        details=(
            f'{profile.clpn_difference_rows} difference samples, dimension {profile.clpn_secret_dimension}, '
            f'effective eta={profile.clpn_difference_noise_rate:g}.'
        ),
    ))

    c_prange = prange_isd_bits(
        profile.clpn_difference_rows,
        profile.clpn_secret_dimension,
        profile.clpn_difference_noise_rate,
    )
    lines.append(AttackLine(
        name='Prange information-set decoding',
        target='CLPN compaction-key row-difference screen',
        bits=c_prange,
        status=_status(c_prange, target_bits),
        details='First-order random-code decoding estimate on row-difference CLPN samples.',
    ))

    c_bkw = bkw_screen_bits(profile.clpn_secret_dimension, params.q, profile.clpn_difference_noise_rate)
    lines.append(AttackLine(
        name='BKW-style parity/noisy-linear learning',
        target='CLPN compaction-key row-difference screen',
        bits=c_bkw,
        status=_status(c_bkw, target_bits),
        details='Coarse q-ary BKW screen for the compaction secret.',
    ))

    # Sparse-row collision/entropy screen.
    collision_excess = math.log2(max(1, profile.gsw_rows)) - 0.5 * profile.sparse_row_entropy_bits
    collision_bits = max(0.0, -collision_excess)
    lines.append(AttackLine(
        name='sparse-row collision entropy',
        target='row-distribution sanity screen',
        bits=profile.sparse_row_entropy_bits,
        status='informational' if collision_excess < 0 else 'collision-risk',
        details=(
            f'row entropy approximately {profile.sparse_row_entropy_bits:.2f} bits; '
            f'birthday excess log2(samples)-H/2 = {collision_excess:.2f}.'
        ),
    ))

    return lines


def security_report(params: SableParams, target_bits: int = 128) -> dict:
    profile = sample_profile(params)
    lines = attack_lines(params, target_bits=target_bits)
    finite_bits = [line.bits for line in lines if line.bits != INF and line.status != 'informational']
    min_bits = min(finite_bits) if finite_bits else INF
    blockers = [asdict(line) for line in lines if line.status in {'critical', 'below-target', 'collision-risk'}]
    return {
        'params': asdict(params),
        'target_bits': target_bits,
        'sample_profile': asdict(profile),
        'minimum_screen_bits': min_bits,
        'passes_screen': bool(min_bits >= target_bits and not blockers),
        'attack_lines': [asdict(line) for line in lines],
        'blockers': blockers,
        'disclaimer': (
            'Screening estimate only.  This is not a certified sparse-LPN/q-ary-LPN security estimate; '
            'it is meant to identify obviously unsafe parameter regimes and guide deeper cryptanalysis.'
        ),
    }


def format_bits(bits: float) -> str:
    if bits == INF:
        return 'inf'
    return f'{bits:.2f}'


def format_report(report: dict) -> str:
    p = report['params']
    profile = report['sample_profile']
    lines: list[str] = []
    lines.append(f"Preset: {p['name']}  target={report['target_bits']} bits")
    lines.append(
        'Samples: '
        f"GSW rows={profile['gsw_rows']} dim={profile['gsw_secret_dimension']} eta={profile['gsw_noise_rate']:.6g}; "
        f"CLPN diff rows={profile['clpn_difference_rows']} dim={profile['clpn_secret_dimension']} "
        f"eta_eff={profile['clpn_difference_noise_rate']:.6g}"
    )
    lines.append(f"Minimum finite screen bits: {format_bits(report['minimum_screen_bits'])}")
    lines.append(f"Passes screening target: {report['passes_screen']}")
    lines.append('Attack screens:')
    for line in report['attack_lines']:
        lines.append(
            f"  - {line['name']} [{line['target']}]: "
            f"bits={format_bits(line['bits'])} status={line['status']}"
        )
        lines.append(f"    {line['details']}")
    if report['blockers']:
        lines.append('Blockers:')
        for line in report['blockers']:
            lines.append(f"  - {line['target']}: {line['name']} at {format_bits(line['bits'])} bits ({line['status']})")
    lines.append(report['disclaimer'])
    return '\n'.join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description='SABLE-HE sparse-LPN/q-ary-LPN attack screening estimator')
    parser.add_argument('--preset', default='toy_noisy', choices=sorted(PRESETS))
    parser.add_argument('--target-bits', type=int, default=128)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    report = security_report(PRESETS[args.preset], target_bits=args.target_bits)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report))


if __name__ == '__main__':
    main()

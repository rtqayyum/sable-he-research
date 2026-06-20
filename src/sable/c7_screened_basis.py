"""C7 screened sparse-basis compactor for SABLE-HE.

C7 is a relation-resistant replacement for the full C4 projective compactor.
The C4 projective dictionary gives one-term decomposition for every nonzero
block coefficient, but it also publishes complete projective lines, which
creates many public weight-3 zero-message relations.  C7 publishes a much
smaller standard-plus-random additive basis and screens candidate masks for
low-weight kernel relations before accepting them.

The design is deliberately conservative:

* the first ``width`` entries of each block are the standard basis, so every
  coefficient block has a guaranteed coordinate decomposition;
* additional dense random masks can reduce the average number of compaction
  terms;
* generation rejects projective duplicates and any basis whose kernel has a
  relation of weight at most ``relation_screen_weight``;
* evaluation first searches for a sparse representation using random masks and
  falls back to the coordinate representation when needed.

This module is a research-validation component.  It does not certify LPN
security; it removes the obvious C4 projective weight-3 relation surface and
reports the remaining public-sample surface for later cryptanalysis.
"""

from __future__ import annotations

import math
import random
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from . import clpn
from .additive_basis import (
    SparseCombination,
    decompose_sparse,
    find_low_weight_relation,
    normalize_projective,
)
from .field import dot_dense, qary_piling_up, repetition_failure_bound
from .params import SableParams
from .qary_lpn_estimator import estimate_qary_lpn_surface
from .sparse import SparseVector

Vector = tuple[int, ...]


def hamming_weight(vec: Sequence[int], q: int) -> int:
    return sum(1 for x in vec if int(x) % q)


def standard_basis(q: int, width: int) -> list[Vector]:
    if width <= 0:
        raise ValueError("width must be positive")
    out: list[Vector] = []
    for i in range(width):
        v = [0] * width
        v[i] = 1 % q
        out.append(tuple(v))
    return out


def _projective_key(vec: Sequence[int], q: int) -> Vector | None:
    norm = normalize_projective(vec, q)
    return None if norm is None else norm[1]


def _random_mask(q: int, width: int, rng: random.Random, min_weight: int) -> Vector:
    if min_weight <= 0:
        raise ValueError("min_weight must be positive")
    if min_weight > width:
        raise ValueError("min_weight cannot exceed width")
    # Prefer dense masks.  Dense masks avoid the immediate relation
    # u - sum_i u_i e_i = 0 having small weight.
    while True:
        vec = tuple(rng.randrange(q) for _ in range(width))
        if hamming_weight(vec, q) >= min_weight:
            return vec


def has_low_weight_relation(q: int, basis: Sequence[Sequence[int]], max_weight: int) -> bool:
    """Return whether the public basis has a kernel relation up to max_weight."""
    if max_weight <= 1:
        return False
    return bool(find_low_weight_relation(q, basis, max_weight, limit=1))


@dataclass(frozen=True)
class C7BasisProfile:
    q: int
    width: int
    basis_entries: int
    standard_entries: int
    random_entries: int
    min_mask_weight: int
    relation_screen_weight: int
    low_weight_relation_found: bool
    guaranteed_coordinate_terms: int
    preferred_random_terms: int

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def generate_screened_basis(
    q: int,
    width: int,
    rng: random.Random,
    *,
    random_entries: int,
    min_mask_weight: int | None = None,
    relation_screen_weight: int = 3,
    max_attempts: int = 50_000,
) -> tuple[list[Vector], C7BasisProfile]:
    """Generate a standard-plus-random basis screened for sparse relations.

    The returned basis always begins with the standard basis.  It then accepts
    up to ``random_entries`` dense random masks.  A candidate is rejected if it
    is projectively duplicate or if adding it creates a kernel relation with
    Hamming weight at most ``relation_screen_weight``.
    """
    if q < 3:
        raise ValueError("q must be at least 3")
    if width <= 0:
        raise ValueError("width must be positive")
    if random_entries < 0:
        raise ValueError("random_entries must be nonnegative")
    if relation_screen_weight < 2:
        raise ValueError("relation_screen_weight must be at least 2")
    if min_mask_weight is None:
        min_mask_weight = min(width, max(1, relation_screen_weight))
    if min_mask_weight > width:
        min_mask_weight = width

    basis = standard_basis(q, width)
    seen_projective: set[Vector] = set()
    for vec in basis:
        key = _projective_key(vec, q)
        if key is not None:
            seen_projective.add(key)

    attempts = 0
    while len(basis) < width + random_entries and attempts < max_attempts:
        attempts += 1
        cand = _random_mask(q, width, rng, min_mask_weight)
        key = _projective_key(cand, q)
        if key is None or key in seen_projective:
            continue
        trial = basis + [cand]
        if has_low_weight_relation(q, trial, relation_screen_weight):
            continue
        seen_projective.add(key)
        basis.append(cand)

    if len(basis) < width + random_entries:
        # This is not a correctness failure: the standard basis still gives
        # full coverage.  It simply means the screened random surface was too
        # constrained for the requested size.
        pass

    profile = C7BasisProfile(
        q=q,
        width=width,
        basis_entries=len(basis),
        standard_entries=width,
        random_entries=max(0, len(basis) - width),
        min_mask_weight=min_mask_weight,
        relation_screen_weight=relation_screen_weight,
        low_weight_relation_found=has_low_weight_relation(q, basis, relation_screen_weight),
        guaranteed_coordinate_terms=width,
        preferred_random_terms=min(2, width) if len(basis) > width else width,
    )
    return basis, profile


@dataclass(frozen=True)
class C7ScreenedBasisKey:
    q: int
    N: int
    block_size: int
    n_c: int
    m_c: int
    preferred_max_terms_per_block: int
    relation_screen_weight: int
    min_mask_weight: int
    random_entries_requested: int
    bases: list[list[Vector]]
    profiles: list[C7BasisProfile]
    blocks: list[list[clpn.CLPNCiphertext]]

    def __post_init__(self) -> None:
        if self.N <= 0:
            raise ValueError("N must be positive")
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")
        expected_blocks = math.ceil(self.N / self.block_size)
        if len(self.bases) != expected_blocks or len(self.blocks) != expected_blocks:
            raise ValueError("incorrect number of C7 blocks")
        if len(self.profiles) != expected_blocks:
            raise ValueError("incorrect number of C7 profiles")
        for block_index, (basis, cts) in enumerate(zip(self.bases, self.blocks)):
            width = self.block_width(block_index)
            if len(basis) != len(cts):
                raise ValueError("basis/ciphertext count mismatch")
            if len(basis) < width:
                raise ValueError("basis must include standard fallback")
            for i, vec in enumerate(basis[:width]):
                expected = [0] * width
                expected[i] = 1 % self.q
                if tuple(expected) != tuple(x % self.q for x in vec):
                    raise ValueError("first width basis entries must be standard basis")
            for vec, ct in zip(basis, cts):
                if len(vec) != width:
                    raise ValueError("basis vector width mismatch")
                if ct.q != self.q or ct.n != self.n_c or ct.m != self.m_c:
                    raise ValueError("incompatible CLPN ciphertext")

    @property
    def num_blocks(self) -> int:
        return len(self.bases)

    @property
    def public_entries(self) -> int:
        return sum(len(block) for block in self.blocks)

    @property
    def public_clpn_rows(self) -> int:
        return self.public_entries * self.m_c

    @property
    def public_field_elements_dense(self) -> int:
        return self.public_entries * self.m_c * (self.n_c + 1)

    @property
    def max_guaranteed_terms_per_block(self) -> int:
        return max((profile.guaranteed_coordinate_terms for profile in self.profiles), default=0)

    def block_width(self, block_index: int) -> int:
        start = block_index * self.block_size
        return max(0, min(self.block_size, self.N - start))

    def to_summary(self) -> dict[str, Any]:
        return {
            "q": self.q,
            "N": self.N,
            "block_size": self.block_size,
            "num_blocks": self.num_blocks,
            "public_entries": self.public_entries,
            "public_clpn_rows": self.public_clpn_rows,
            "preferred_max_terms_per_block": self.preferred_max_terms_per_block,
            "guaranteed_max_terms_per_block": self.max_guaranteed_terms_per_block,
            "relation_screen_weight": self.relation_screen_weight,
            "random_entries_requested": self.random_entries_requested,
            "random_entries_actual": sum(p.random_entries for p in self.profiles),
            "low_weight_relation_found": any(p.low_weight_relation_found for p in self.profiles),
        }


def _secret_blocks(tilde_s: Sequence[int], block_size: int) -> list[list[int]]:
    return [list(tilde_s[start : start + block_size]) for start in range(0, len(tilde_s), block_size)]


def build_screened_basis_key(
    tilde_s: list[int],
    secret_r: list[int],
    params: SableParams,
    rng: random.Random,
    *,
    block_size: int | None = None,
    random_entries_per_block: int | None = None,
    preferred_max_terms_per_block: int = 2,
    relation_screen_weight: int = 3,
    min_mask_weight: int | None = None,
    max_attempts: int = 50_000,
) -> C7ScreenedBasisKey:
    q = params.q
    N = len(tilde_s)
    ell = params.c2_block_size if block_size is None else block_size
    if N != params.N:
        raise ValueError("tilde_s length must equal params.N")
    if len(secret_r) != params.n_c:
        raise ValueError("compaction secret length mismatch")
    if ell <= 0:
        raise ValueError("block_size must be positive")
    if random_entries_per_block is None:
        random_entries_per_block = max(0, 2 * ell)
    bases: list[list[Vector]] = []
    profiles: list[C7BasisProfile] = []
    blocks: list[list[clpn.CLPNCiphertext]] = []
    actual_min_weight = min_mask_weight if min_mask_weight is not None else min(ell, max(1, relation_screen_weight))
    for s_block in _secret_blocks(tilde_s, ell):
        basis, profile = generate_screened_basis(
            q,
            len(s_block),
            rng,
            random_entries=random_entries_per_block,
            min_mask_weight=min_mask_weight,
            relation_screen_weight=relation_screen_weight,
            max_attempts=max_attempts,
        )
        cts = [clpn.encrypt(dot_dense(vec, s_block, q), secret_r, params, rng) for vec in basis]
        bases.append(basis)
        profiles.append(profile)
        blocks.append(cts)
    return C7ScreenedBasisKey(
        q=q,
        N=N,
        block_size=ell,
        n_c=params.n_c,
        m_c=params.m_c,
        preferred_max_terms_per_block=preferred_max_terms_per_block,
        relation_screen_weight=relation_screen_weight,
        min_mask_weight=actual_min_weight,
        random_entries_requested=random_entries_per_block,
        bases=bases,
        profiles=profiles,
        blocks=blocks,
    )


def coeff_blocks(coeffs: SparseVector, block_size: int) -> list[Vector]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    q = coeffs.q
    return [
        tuple(coeffs.data.get(start + j, 0) % q for j in range(min(block_size, coeffs.length - start)))
        for start in range(0, coeffs.length, block_size)
    ]


def coordinate_combination(block_coeffs: Sequence[int], q: int) -> SparseCombination:
    terms = tuple((i, int(c) % q) for i, c in enumerate(block_coeffs) if int(c) % q)
    return SparseCombination(len(block_coeffs), q, terms)


def decompose_block(
    block_coeffs: Sequence[int],
    basis: Sequence[Sequence[int]],
    q: int,
    preferred_max_terms: int,
) -> SparseCombination:
    """Return a sparse decomposition, falling back to coordinates."""
    if not any(int(x) % q for x in block_coeffs):
        return SparseCombination(len(block_coeffs), q, tuple())
    try:
        return decompose_sparse(block_coeffs, basis, q, preferred_max_terms)
    except ValueError:
        return coordinate_combination(block_coeffs, q)


def eval_lin(coeffs: SparseVector, key: C7ScreenedBasisKey) -> clpn.CLPNCiphertext:
    if coeffs.length != key.N or coeffs.q != key.q:
        raise ValueError("coefficient vector incompatible with C7 key")
    acc = clpn.CLPNCiphertext.zero(key.m_c, key.n_c, key.q)
    for block_index, block_coeffs in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block_coeffs):
            continue
        comb = decompose_block(block_coeffs, key.bases[block_index], key.q, key.preferred_max_terms_per_block)
        for basis_index, scalar in comb.terms:
            acc = acc.add_scaled(key.blocks[block_index][basis_index], scalar)
    return acc


def compaction_term_count(coeffs: SparseVector, key: C7ScreenedBasisKey) -> int:
    total = 0
    for block_index, block_coeffs in enumerate(coeff_blocks(coeffs, key.block_size)):
        if not any(block_coeffs):
            continue
        total += decompose_block(block_coeffs, key.bases[block_index], key.q, key.preferred_max_terms_per_block).weight
    return total


def decrypt_c7(ciphertext: clpn.CLPNCiphertext, secret_r: list[int]) -> int:
    return clpn.decrypt(ciphertext, secret_r)


def estimate_c7_key(
    params: SableParams,
    *,
    block_size: int | None = None,
    random_entries_per_block: int | None = None,
    preferred_max_terms_per_block: int = 2,
    relation_screen_weight: int = 3,
) -> dict[str, Any]:
    q = params.q
    ell = params.c2_block_size if block_size is None else block_size
    if random_entries_per_block is None:
        random_entries_per_block = max(0, 2 * ell)
    widths = [min(ell, params.N - start) for start in range(0, params.N, ell)]
    c7_entries = sum(w + random_entries_per_block for w in widths)
    c4_entries = sum((q**w - 1) // (q - 1) for w in widths)
    c2_entries = sum(q**w - 1 for w in widths)
    v1_entries = params.N
    guaranteed_terms_bound = sum(widths)
    preferred_terms_bound = len(widths) * preferred_max_terms_per_block
    eta_preferred = qary_piling_up(q, params.eta_c, preferred_terms_bound)
    eta_guaranteed = qary_piling_up(q, params.eta_c, guaranteed_terms_bound)
    return {
        "params": params.name,
        "q": q,
        "N": params.N,
        "block_size": ell,
        "num_blocks": len(widths),
        "random_entries_per_block": random_entries_per_block,
        "relation_screen_weight": relation_screen_weight,
        "preferred_max_terms_per_block": preferred_max_terms_per_block,
        "v1_coordinate_entries": v1_entries,
        "c2_full_dictionary_entries": c2_entries,
        "c4_projective_entries": c4_entries,
        "c7_screened_entries_est": c7_entries,
        "c7_vs_c4_entry_ratio": c7_entries / c4_entries if c4_entries else 0.0,
        "c7_vs_c2_entry_ratio": c7_entries / c2_entries if c2_entries else 0.0,
        "c7_public_clpn_rows_est": c7_entries * params.m_c,
        "preferred_terms_bound": preferred_terms_bound,
        "guaranteed_coordinate_terms_bound": guaranteed_terms_bound,
        "eta_preferred_bound": eta_preferred,
        "eta_guaranteed_bound": eta_guaranteed,
        "repetition_failure_bound_preferred": repetition_failure_bound(params.m_c, eta_preferred),
        "repetition_failure_bound_guaranteed": repetition_failure_bound(params.m_c, eta_guaranteed),
        "known_weight3_projective_surface": "removed by not publishing full projective lines; screened empirically up to relation_screen_weight",
    }


@dataclass(frozen=True)
class C7SurfaceReport:
    params: dict[str, Any]
    estimate: dict[str, Any]
    built_key_summary: dict[str, Any] | None
    row_difference_samples: int
    row_difference_noise: float
    screened_relation_weight: int
    low_weight_relation_found: bool
    lpn_screens: list[dict[str, Any]]
    verdict: str
    blockers: list[str]
    interpretation: str

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def estimate_c7_surface(
    params: SableParams,
    *,
    block_size: int | None = None,
    random_entries_per_block: int | None = None,
    preferred_max_terms_per_block: int = 2,
    relation_screen_weight: int = 3,
    target_bits: float = 128.0,
    seed: int | None = None,
    build_key: bool = False,
) -> C7SurfaceReport:
    est = estimate_c7_key(
        params,
        block_size=block_size,
        random_entries_per_block=random_entries_per_block,
        preferred_max_terms_per_block=preferred_max_terms_per_block,
        relation_screen_weight=relation_screen_weight,
    )
    key_summary: dict[str, Any] | None = None
    low_rel_found = False
    if build_key:
        # Build against a dummy secret to screen the actual random bases.  This
        # may be large; experiments use toy/small presets only.
        rng = random.Random(seed)
        dummy_s = [rng.randrange(params.q) for _ in range(params.N)]
        dummy_r = [rng.randrange(params.q) for _ in range(params.n_c)]
        key = build_screened_basis_key(
            dummy_s,
            dummy_r,
            params,
            rng,
            block_size=block_size,
            random_entries_per_block=random_entries_per_block,
            preferred_max_terms_per_block=preferred_max_terms_per_block,
            relation_screen_weight=relation_screen_weight,
        )
        key_summary = key.to_summary()
        low_rel_found = bool(key_summary["low_weight_relation_found"])
    entries = int(est["c7_screened_entries_est"])
    row_diff_samples = entries * (params.m_c * (params.m_c - 1) // 2)
    eta2 = qary_piling_up(params.q, params.eta_c, 2)
    screens = [
        estimate_qary_lpn_surface(
            name="C7_expansion_key_sparse_LPN_rows",
            n=params.n,
            q=params.q,
            eta=params.eta,
            samples=params.N * params.N,
            row_weight=params.k,
            target_bits=target_bits,
        ),
        estimate_qary_lpn_surface(
            name="C7_CLPN_row_differences",
            n=params.n_c,
            q=params.q,
            eta=eta2,
            samples=max(1, row_diff_samples),
            row_weight=None,
            target_bits=target_bits,
        ),
    ]
    blockers: list[str] = []
    if low_rel_found:
        blockers.append("constructed C7 basis still has a low-weight relation within the configured screen")
    for screen in screens:
        if not screen.get("passes_target_screen", False):
            blockers.append(f"{screen['name']} does not pass target screen")
        for warning in screen.get("warnings", [])[:3]:
            if "large public" in warning or "below" in warning or "zero noise" in warning:
                blockers.append(f"{screen['name']}: {warning}")
    verdict = "passes-c7-structural-screen" if not blockers else "research-only-needs-parameter-hardening"
    return C7SurfaceReport(
        params=asdict(params),
        estimate=est,
        built_key_summary=key_summary,
        row_difference_samples=row_diff_samples,
        row_difference_noise=eta2,
        screened_relation_weight=relation_screen_weight,
        low_weight_relation_found=low_rel_found,
        lpn_screens=screens,
        verdict=verdict,
        blockers=blockers,
        interpretation=(
            "C7 removes the explicit C4 full-projective weight-3 relation surface by using an incomplete screened basis. "
            "Coverage is guaranteed by the coordinate fallback, while random dense masks reduce average compaction terms when sparse decomposition succeeds. "
            "This is still a screening result, not a proof of concrete post-quantum security."
        ),
    )


def format_c7_surface(report: C7SurfaceReport) -> str:
    e = report.estimate
    lines = [
        f"C7 screened-basis surface report for {report.params['name']}",
        f"q={e['q']} N={e['N']} block_size={e['block_size']} blocks={e['num_blocks']}",
        f"entries: v1={e['v1_coordinate_entries']} C4_projective={e['c4_projective_entries']} C7_est={e['c7_screened_entries_est']} C2={e['c2_full_dictionary_entries']}",
        f"C7/C4={e['c7_vs_c4_entry_ratio']:.6g} C7/C2={e['c7_vs_c2_entry_ratio']:.6g}",
        f"preferred terms bound={e['preferred_terms_bound']} eta={e['eta_preferred_bound']:.6g}",
        f"guaranteed coordinate terms bound={e['guaranteed_coordinate_terms_bound']} eta={e['eta_guaranteed_bound']:.6g}",
        f"row-difference samples={report.row_difference_samples} eta2={report.row_difference_noise:.6g}",
        f"screened relation weight <= {report.screened_relation_weight}; low relation found={report.low_weight_relation_found}",
        f"verdict={report.verdict}",
    ]
    if report.built_key_summary is not None:
        lines.append(f"built key summary={report.built_key_summary}")
    lines.append("LPN screens:")
    for screen in report.lpn_screens:
        lines.append(
            f"  - {screen['name']}: samples={screen['samples']} eta={screen['eta']} min_bits={screen.get('conservative_min_bits')} passes={screen.get('passes_target_screen')}"
        )
    if report.blockers:
        lines.append("Blockers:")
        for blocker in report.blockers:
            lines.append(f"  - {blocker}")
    lines.append(report.interpretation)
    return "\n".join(lines)


C7BasisKey = C7ScreenedBasisKey
build_c7_screened_basis_key = build_screened_basis_key
eval_lin_c7 = eval_lin
terms_used = compaction_term_count

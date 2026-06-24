"""Phase 10 compaction-theory helpers for SABLE-HE.

This module is intentionally mathematical and review-oriented.  It does not
claim a production-secure parameter set.  Its purpose is to formalize the
relation-resistant compaction design choice used by SABLE-HE and to provide
small, reproducible checks for public mask families.
"""

from __future__ import annotations

import itertools
import json
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .version import __release_name__, __version__


@dataclass(frozen=True)
class MaskFamily:
    """A public compaction mask family U subset F_q^b."""

    name: str
    q: int
    block_width: int
    masks: tuple[tuple[int, ...], ...]
    description: str

    @property
    def entries_per_block(self) -> int:
        return len(self.masks)

    def to_jsonable(self) -> dict:
        d = asdict(self)
        d["masks"] = [list(row) for row in self.masks]
        d["entries_per_block"] = self.entries_per_block
        return d


@dataclass(frozen=True)
class KernelDistanceResult:
    """Sparse-kernel screen for known-zero public mask relations."""

    q: int
    block_width: int
    entries: int
    searched_up_to_weight: int
    minimum_relation_weight: int | None
    relation_indices: tuple[int, ...] | None
    relation_vectors: tuple[tuple[int, ...], ...] | None
    status: str

    def to_jsonable(self) -> dict:
        return {
            "q": self.q,
            "block_width": self.block_width,
            "entries": self.entries,
            "searched_up_to_weight": self.searched_up_to_weight,
            "minimum_relation_weight": self.minimum_relation_weight,
            "relation_indices": list(self.relation_indices) if self.relation_indices else None,
            "relation_vectors": [list(v) for v in self.relation_vectors] if self.relation_vectors else None,
            "status": self.status,
        }


@dataclass(frozen=True)
class CompactionAnalysis:
    """Review-facing summary of one compaction family."""

    family: str
    q: int
    block_width: int
    blocks: int
    entries_per_block: int
    total_public_entries: int
    clpn_rows_per_entry: int
    total_public_clpn_rows: int
    active_blocks: int
    worst_case_noise_terms: int
    effective_compaction_error: float
    sparse_kernel_screen: KernelDistanceResult
    relation_resistance_claim: str
    suggested_role: str
    notes: tuple[str, ...]

    def to_jsonable(self) -> dict:
        return {
            "family": self.family,
            "q": self.q,
            "block_width": self.block_width,
            "blocks": self.blocks,
            "entries_per_block": self.entries_per_block,
            "total_public_entries": self.total_public_entries,
            "clpn_rows_per_entry": self.clpn_rows_per_entry,
            "total_public_clpn_rows": self.total_public_clpn_rows,
            "active_blocks": self.active_blocks,
            "worst_case_noise_terms": self.worst_case_noise_terms,
            "effective_compaction_error": self.effective_compaction_error,
            "sparse_kernel_screen": self.sparse_kernel_screen.to_jsonable(),
            "relation_resistance_claim": self.relation_resistance_claim,
            "suggested_role": self.suggested_role,
            "notes": list(self.notes),
        }


def compaction_theory_info() -> dict:
    return {
        "package": "sable-he-research",
        "version": __version__,
        "release_name": __release_name__,
        "phase": "Phase 10 compaction theory framework",
        "status": "internal top-venue strengthening package; not production cryptography",
        "main_contribution": (
            "formalizes SABLE-HE compaction as public mask-family code/LPN compaction "
            "and separates correctness from sparse public-relation resistance"
        ),
        "core_objects": [
            "mask family U subset F_q^b",
            "blockwise CLPN encryption of <u, s_B>",
            "sparse mask-kernel distance d_perp(U)",
            "q-ary compaction-noise piling-up",
            "relation-resistant coordinate compaction theorem",
        ],
        "non_goals": [
            "not an independent cryptanalysis result",
            "not a certified parameter set",
            "not a proof that richer block dictionaries are always secure",
            "not a replacement for external LPN/ISD/BKW review",
        ],
    }


def normalize_projective(vec: Sequence[int], q: int) -> tuple[int, ...]:
    values = tuple(int(x) % q for x in vec)
    if all(x == 0 for x in values):
        raise ValueError("zero vector has no projective representative")
    for x in values:
        if x != 0:
            inv = pow(x, -1, q)
            return tuple((v * inv) % q for v in values)
    raise AssertionError("unreachable")


def nonzero_vectors(q: int, b: int) -> list[tuple[int, ...]]:
    out: list[tuple[int, ...]] = []
    for vec in itertools.product(range(q), repeat=b):
        if any(vec):
            out.append(tuple(vec))
    return out


def coordinate_family(q: int, block_width: int) -> MaskFamily:
    masks = []
    for i in range(block_width):
        row = [0] * block_width
        row[i] = 1
        masks.append(tuple(row))
    return MaskFamily(
        name="coordinate",
        q=q,
        block_width=block_width,
        masks=tuple(masks),
        description="standard basis masks; main relation-resistant SABLE-HE compactor",
    )


def full_dictionary_family(q: int, block_width: int) -> MaskFamily:
    return MaskFamily(
        name="full-block-dictionary",
        q=q,
        block_width=block_width,
        masks=tuple(nonzero_vectors(q, block_width)),
        description="all nonzero block masks; low compaction noise but very large public relation surface",
    )


def projective_family(q: int, block_width: int) -> MaskFamily:
    reps = sorted({normalize_projective(v, q) for v in nonzero_vectors(q, block_width)})
    return MaskFamily(
        name="projective-block-dictionary",
        q=q,
        block_width=block_width,
        masks=tuple(reps),
        description="one representative per projective line; smaller than full dictionary but still relation-rich",
    )


def screened_random_family(q: int, block_width: int, entries: int, seed: int = 1234) -> MaskFamily:
    if entries < block_width:
        raise ValueError("entries must be at least block_width")
    rng = random.Random(seed)
    base = list(coordinate_family(q, block_width).masks)
    seen = set(base)
    vectors = nonzero_vectors(q, block_width)
    while len(base) < entries and len(seen) < len(vectors):
        v = tuple(rng.choice(range(q)) for _ in range(block_width))
        if any(v) and v not in seen:
            seen.add(v)
            base.append(v)
    return MaskFamily(
        name=f"screened-random-{entries}",
        q=q,
        block_width=block_width,
        masks=tuple(base),
        description="coordinate basis plus random masks; experimental only pending sparse-kernel screening",
    )


def rank_mod(matrix: Sequence[Sequence[int]], q: int) -> int:
    rows = [[int(x) % q for x in row] for row in matrix if any(int(x) % q for x in row)]
    if not rows:
        return 0
    m = len(rows)
    n = len(rows[0])
    rank = 0
    col = 0
    while rank < m and col < n:
        pivot = None
        for r in range(rank, m):
            if rows[r][col] % q:
                pivot = r
                break
        if pivot is None:
            col += 1
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inv = pow(rows[rank][col] % q, -1, q)
        rows[rank] = [(v * inv) % q for v in rows[rank]]
        for r in range(m):
            if r != rank and rows[r][col] % q:
                factor = rows[r][col] % q
                rows[r] = [(rows[r][c] - factor * rows[rank][c]) % q for c in range(n)]
        rank += 1
        col += 1
    return rank


def sparse_kernel_screen(family: MaskFamily, max_weight: int = 4) -> KernelDistanceResult:
    masks = list(family.masks)
    max_w = min(max_weight, len(masks))
    for w in range(1, max_w + 1):
        for idxs in itertools.combinations(range(len(masks)), w):
            subset = [masks[i] for i in idxs]
            if rank_mod(subset, family.q) < w:
                return KernelDistanceResult(
                    q=family.q,
                    block_width=family.block_width,
                    entries=len(masks),
                    searched_up_to_weight=max_weight,
                    minimum_relation_weight=w,
                    relation_indices=tuple(idxs),
                    relation_vectors=tuple(subset),
                    status="relation-found",
                )
    return KernelDistanceResult(
        q=family.q,
        block_width=family.block_width,
        entries=len(masks),
        searched_up_to_weight=max_weight,
        minimum_relation_weight=None,
        relation_indices=None,
        relation_vectors=None,
        status=f"no-relation-found-up-to-{max_weight}",
    )


def qary_piling_up(q: int, eta: float, terms: int) -> float:
    if terms <= 0:
        return 0.0
    return ((q - 1) / q) * (1.0 - (1.0 - (q * eta) / (q - 1)) ** terms)


def build_family(kind: str, q: int, block_width: int, entries: int | None = None, seed: int = 1234) -> MaskFamily:
    kind = kind.lower()
    if kind in {"coordinate", "basis", "main"}:
        return coordinate_family(q, block_width)
    if kind in {"projective", "projective-block", "projective-block-dictionary"}:
        return projective_family(q, block_width)
    if kind in {"full", "full-block", "full-block-dictionary"}:
        return full_dictionary_family(q, block_width)
    if kind in {"screened-random", "random"}:
        return screened_random_family(q, block_width, entries or max(2 * block_width, block_width + 1), seed=seed)
    raise ValueError(f"unknown compaction family: {kind}")


def analyze_compaction_family(
    kind: str = "coordinate",
    *,
    q: int = 31,
    n: int = 512,
    block_width: int = 1,
    active_blocks: int | None = None,
    m_c: int = 192,
    eta_c: float = 2 ** -12,
    max_relation_weight: int = 4,
    entries: int | None = None,
    seed: int = 1234,
) -> CompactionAnalysis:
    family = build_family(kind, q=q, block_width=block_width, entries=entries, seed=seed)
    blocks = math.ceil((n + 1) / block_width)
    active = active_blocks if active_blocks is not None else blocks
    if family.name == "coordinate":
        worst_case_terms = min(n + 1, active * block_width)
        role = "main-scheme-default"
        claim = "mask matrix is a standard basis; no nonzero known-zero mask-kernel relation exists inside a block"
    elif "projective" in family.name or "full" in family.name:
        worst_case_terms = active
        role = "not-main; relation-surface demonstration or optional only after external review"
        claim = "low per-block noise, but public mask family has low-weight known-zero relations for block_width >= 2"
    else:
        worst_case_terms = active
        role = "experimental optimization pending sparse-kernel screening and external review"
        claim = "depends on generated mask matrix and sparse-kernel screening bound"
    screen = sparse_kernel_screen(family, max_weight=max_relation_weight)
    total_entries = blocks * family.entries_per_block
    total_rows = total_entries * m_c
    notes = [
        "Correctness follows from CLPN linear homomorphism: Enc(<u,s_B>) terms add to Enc(<alpha,s_B>).",
        "Security screening focuses on known-zero public mask relations U^T z = 0 and derived CLPN row-difference surfaces.",
        "The screen is finite and conservative; absence of a low-weight relation up to the search bound is not a proof of global security.",
    ]
    if family.name == "coordinate":
        notes += [
            "Coordinate compaction accumulates more CLPN noise terms than block dictionaries.",
            "Its advantage is a minimal public mask surface and no intra-block mask-kernel relation.",
        ]
    if screen.minimum_relation_weight is not None:
        notes += [f"Sparse-kernel screen found a relation of weight {screen.minimum_relation_weight}."]
    else:
        notes += [f"No sparse-kernel relation found up to weight {max_relation_weight}."]
    return CompactionAnalysis(
        family=family.name,
        q=q,
        block_width=block_width,
        blocks=blocks,
        entries_per_block=family.entries_per_block,
        total_public_entries=total_entries,
        clpn_rows_per_entry=m_c,
        total_public_clpn_rows=total_rows,
        active_blocks=active,
        worst_case_noise_terms=worst_case_terms,
        effective_compaction_error=qary_piling_up(q, eta_c, worst_case_terms),
        sparse_kernel_screen=screen,
        relation_resistance_claim=claim,
        suggested_role=role,
        notes=tuple(notes),
    )


def comparison_table(q: int = 31, n: int = 512, block_width: int = 2, m_c: int = 192) -> list[dict]:
    rows = []
    for kind in ["coordinate", "projective", "full"]:
        b = 1 if kind == "coordinate" else block_width
        report = analyze_compaction_family(kind, q=q, n=n, block_width=b, m_c=m_c)
        row = report.to_jsonable()
        row.pop("notes", None)
        row.pop("sparse_kernel_screen", None)
        rows.append(row)
    return rows


def theorem_statements() -> list[dict]:
    return [
        {
            "name": "Mask-family compaction correctness",
            "statement": (
                "Let U_B be a public mask family for each secret block s_B. If each active coefficient block alpha_B "
                "is represented as a linear combination of masks in U_B, then CLPN linear evaluation returns an encryption "
                "of the final GSW last-row inner product."
            ),
            "proof_idea": "Expand alpha_B = sum z_j u_j and apply CLPN linear homomorphism block by block.",
        },
        {
            "name": "Coordinate relation-resistance",
            "statement": (
                "For U = I_b, the only vector z satisfying U^T z = 0 is z = 0; therefore there is no intra-block known-zero "
                "mask relation among distinct coordinate entries."
            ),
            "proof_idea": "U^T is the identity map on F_q^b.",
        },
        {
            "name": "Projective/full dictionary relation warning",
            "statement": (
                "For b >= 2, full and projective block dictionaries contain low-weight public mask relations, often of weight 3, "
                "which can cancel the encrypted block secret and produce known-zero CLPN-style samples."
            ),
            "proof_idea": "Any two-dimensional subspace contains three projective points with a nontrivial linear dependency.",
        },
        {
            "name": "Compaction noise piling-up",
            "statement": (
                "If T nonzero CLPN error terms with q-ary symmetric error rate eta_c are linearly combined, the effective error "
                "rate is ((q-1)/q)*(1-(1-q*eta_c/(q-1))^T)."
            ),
            "proof_idea": "Use additive characters of F_q and multiply nontrivial Fourier coefficients.",
        },
    ]


def review_checklist() -> list[dict]:
    return [
        {"category": "correctness", "question": "Does each active final-row block have a valid mask decomposition?"},
        {"category": "correctness", "question": "Is the q-ary compaction-noise budget below the chosen decoder threshold?"},
        {"category": "relations", "question": "What is the minimum sparse kernel weight of every public mask matrix U?"},
        {"category": "relations", "question": "Can public mask relations be combined with CLPN row differences to amplify LPN samples?"},
        {"category": "security", "question": "Are all CLPN public rows counted in the dense q-ary LPN sample surface?"},
        {"category": "security", "question": "Does any optimized mask family introduce structure not present in random code/LPN assumptions?"},
        {"category": "paper", "question": "Does the manuscript clearly present coordinate compaction as the conservative main proposal?"},
    ]


def write_compaction_package(
    output: str | Path,
    *,
    q: int = 31,
    n: int = 512,
    block_width: int = 2,
    m_c: int = 192,
    eta_c: float = 2 ** -12,
    max_relation_weight: int = 4,
) -> dict:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    reports = {
        "coordinate": analyze_compaction_family("coordinate", q=q, n=n, block_width=1, m_c=m_c, eta_c=eta_c, max_relation_weight=max_relation_weight).to_jsonable(),
        "projective": analyze_compaction_family("projective", q=q, n=n, block_width=block_width, m_c=m_c, eta_c=eta_c, max_relation_weight=max_relation_weight).to_jsonable(),
        "full": analyze_compaction_family("full", q=q, n=n, block_width=block_width, m_c=m_c, eta_c=eta_c, max_relation_weight=max_relation_weight).to_jsonable(),
    }
    manifest = {
        "schema": "sable-phase10-compaction-package-v1",
        "version": __version__,
        "release_name": __release_name__,
        "status": "review package; not independent cryptanalysis",
        "files": [
            "compaction_theory_info.json",
            "theorem_statements.json",
            "review_checklist.json",
            "compaction_family_reports.json",
            "compaction_summary.md",
        ],
    }
    (out / "compaction_theory_info.json").write_text(json.dumps(compaction_theory_info(), indent=2) + "\n", encoding="utf-8")
    (out / "theorem_statements.json").write_text(json.dumps(theorem_statements(), indent=2) + "\n", encoding="utf-8")
    (out / "review_checklist.json").write_text(json.dumps(review_checklist(), indent=2) + "\n", encoding="utf-8")
    (out / "compaction_family_reports.json").write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# SABLE-HE Phase 10 Compaction Theory Review Package",
        "",
        f"Version: {__version__}",
        "",
        "This package formalizes relation-resistant compaction as a public mask-family problem.",
        "Coordinate compaction is the conservative main proposal. Richer block dictionaries are included for comparison and review only.",
        "",
        "## Family summary",
    ]
    for name, rep in reports.items():
        lines.append(
            f"- {name}: entries/block={rep['entries_per_block']}, total CLPN rows={rep['total_public_clpn_rows']}, "
            f"noise terms={rep['worst_case_noise_terms']}, role={rep['suggested_role']}"
        )
    (out / "compaction_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest["files"].append("MANIFEST.json")
    return {"output": str(out), **manifest}

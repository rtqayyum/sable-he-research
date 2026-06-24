"""Formal proof-strengthening utilities for SABLE-HE.

The functions in this module generate proof-facing artifacts: a security-game
specification, theorem/proof obligations, hybrid steps, and sample-count ledgers.
They are intended for paper writing and external cryptographic review. They do
not certify concrete SABLE-HE parameters.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from .params import PRESETS, SableParams
from .version import __release_name__, __version__

SCHEMA = "sable-phase6-formal-proof-package-v1"


@dataclass(frozen=True)
class ProofObligation:
    identifier: str
    category: str
    statement: str
    proof_strategy: str
    dependencies: list[str]
    reviewer_risk: str
    status: str = "draft-formalized"

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HybridStep:
    step: str
    name: str
    replaced_distribution: str
    assumption: str
    sample_surface: str
    proof_note: str

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SampleLedger:
    preset: str
    q: int
    n: int
    N: int
    k: int
    eta: float
    n_c: int
    m_c: int
    eta_c: float
    replicas: int
    depth: int
    additions: int
    fl_clients: int
    model_length: int
    expansion_key_rows: int
    expansion_sparse_entries_upper_bound: int
    compaction_key_rows: int
    same_entry_row_differences: int
    input_ciphertext_rows: int
    deployment_ciphertext_values: int
    estimated_fresh_support: int
    estimated_depth_support_bound: int
    estimated_final_failure_bound: float

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def proof_info() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "version": __version__,
        "release_name": __release_name__,
        "phase": "formal-proof-strengthening",
        "status": "proof-package-ready-for-review; not independently cryptanalyzed",
        "scope": [
            "secret-key IND-CPA game with public evaluation keys",
            "correctness obligations for compact encryption, expansion, evaluation, and compaction",
            "hybrid sequence for replacing compaction key, expansion key, oracle ciphertexts, and challenge ciphertext",
            "sample-count ledger for public LPN/code surfaces",
        ],
        "not_claimed": [
            "certified 128/192/256-bit parameters",
            "CCA security",
            "bootstrapped/full FHE",
            "side-channel security",
            "NIST/FIPS validation",
            "independent cryptanalysis",
        ],
    }


def security_game_spec() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "game": "SABLE-HE secret-key IND-CPA with public evaluation keys",
        "public_objects": ["parameter set", "expansion key EK_exp", "compaction key EK_cmp", "public evaluation algorithms"],
        "secret_objects": ["compact input secret t", "evaluation secret s", "compaction secret r"],
        "oracles": [
            "Enc(mu): returns compact SABLE ciphertext replicas under t",
            "Challenge(mu0, mu1): returns an encryption of mu_b for hidden b",
        ],
        "adversary_capabilities": [
            "polynomially many encryption queries",
            "arbitrary public homomorphic evaluation",
            "access to all public keys and algorithm descriptions",
        ],
        "security_claim": "The challenge bit is hidden under sparse q-ary LPN and q-ary LPN/code pseudorandomness for the stated public sample counts.",
        "excluded": [
            "chosen-ciphertext queries",
            "malicious parameter generation",
            "side channels and timing leakage",
            "decryption-failure oracle leakage",
            "concrete security certification",
        ],
    }


def proof_obligations() -> list[ProofObligation]:
    return [
        ProofObligation("O1", "assumption", "Sparse q-ary LPN zero encryptions are pseudorandom for the exact support/noise/sample distribution.", "Reduce zero-vector indistinguishability to sparse q-ary LPN and bind all public rows to the sample ledger.", ["Sparse q-ary LPN"], "Low-noise and high-sample regimes require external attack review."),
        ProofObligation("O2", "correctness", "Compact input ciphertexts satisfy c dot t_tilde = mu + e.", "Expand the finite-field inner product using t_tilde=(-t,1).", ["field arithmetic"], "Implementation must preserve canonical sparse vector semantics."),
        ProofObligation("O3", "correctness", "GSW-style scalar matrices satisfy X s_tilde = alpha s_tilde + e.", "Write X as a sparse-LPN zero matrix plus alpha times identity.", ["Sparse-LPN zero rows"], "Sign conventions and final-coordinate normalization must be checked."),
        ProofObligation("O4", "correctness", "Expansion maps compact input ciphertexts under t to GSW-style ciphertexts under s.", "Use linearity of expansion-key encryptions of t_tilde coordinates.", ["O2", "O3"], "Expansion-key rows must be counted as public sparse-LPN samples."),
        ProofObligation("O5", "correctness", "Addition preserves the good-ciphertext invariant.", "Apply linearity and a coordinatewise union bound.", ["good ciphertext definition"], "The bound is conservative but safe."),
        ProofObligation("O6", "correctness", "Multiplication preserves the good-ciphertext invariant with row-support-dependent error growth.", "Expand C1 C2 s_tilde = C1(mu2 s_tilde + e2) and bound C1 e2 by row support.", ["good ciphertext definition", "row-sparse multiplication"], "This is the main low-depth bottleneck and should be independently checked."),
        ProofObligation("O7", "correctness", "Compaction evaluates the last-row decryption form using q-ary code/LPN linear homomorphism.", "Evaluate rho dot s_tilde on CLPN encryptions of s_tilde coordinates.", ["CLPN linear homomorphism"], "Row-difference surfaces in the compaction key need explicit accounting."),
        ProofObligation("O8", "correctness", "Replicated plurality decoding amplifies correctness when per-replica failure is below one half.", "Apply a Hoeffding/Chernoff-style tail bound to independent replicas.", ["independent encryption randomness"], "Seed reuse would invalidate the independence claim."),
        ProofObligation("O9", "security", "Compaction-key replacement is justified by q-ary LPN/code semantic security.", "Hybrid H0->H1 replaces CLPN encryptions of s_tilde by pseudorandom samples.", ["q-ary LPN/code security"], "Derived row-difference samples must be counted."),
        ProofObligation("O10", "security", "Expansion-key replacement is justified by sparse q-ary LPN security.", "Hybrid H1->H2 replaces sparse-LPN GSW rows after conditioning on fixed diagonal shifts.", ["Sparse q-ary LPN"], "Review whether public diagonal shifts create any nonstandard leakage."),
        ProofObligation("O11", "security", "Encryption-oracle and challenge ciphertext replacement is justified by sparse q-ary LPN security.", "Hybrid H2->H3 replaces message-shifted input ciphertext samples by pseudorandom vectors.", ["Sparse q-ary LPN"], "Deployment query volume must be bounded."),
        ProofObligation("O12", "security", "The final hybrid is challenge-bit independent.", "After all replacements, no public value depends on the challenge bit except through negligible hybrid gaps.", ["O9", "O10", "O11"], "Only IND-CPA is claimed."),
    ]


def hybrid_steps() -> list[HybridStep]:
    return [
        HybridStep("H0", "real experiment", "none", "none", "all public surfaces are real", "Baseline IND-CPA experiment."),
        HybridStep("H1", "replace compaction key", "CLPN encryptions of coordinates of s_tilde", "q-ary LPN/code pseudorandomness", "(n+1)m_c direct rows plus row-difference surfaces", "Messages are independent of compaction secret r."),
        HybridStep("H2", "replace expansion key", "GSW encryptions of coordinates of t_tilde", "sparse q-ary LPN pseudorandomness", "(n+1)^2 sparse-LPN rows", "Messages are independent of evaluation secret s."),
        HybridStep("H3", "replace encryption-oracle outputs", "compact sparse-LPN encryptions of chosen plaintexts", "sparse q-ary LPN pseudorandomness", "deployment-dependent encryption-query rows", "After key replacement, oracle outputs can be simulated as pseudorandom sparse-supported samples."),
        HybridStep("H4", "replace challenge ciphertext", "challenge encryption of mu_b", "sparse q-ary LPN pseudorandomness", "one challenge ciphertext plus replicas", "The adversary view becomes independent of b; advantage is bounded by hybrid gaps."),
    ]


def _fresh_support_bound(params: SableParams) -> int:
    return (int(params.k) + 1) * (int(params.k) + 2)


def _depth_support_bound(w0: int, depth: int) -> int:
    w = max(1, w0)
    for _ in range(max(0, depth)):
        w = w * w
    return w


def _failure_bound(params: SableParams, depth: int, additions: int) -> float:
    w0 = _fresh_support_bound(params)
    eps = (int(params.k) + 2) * float(params.eta)
    w = w0
    for _ in range(max(0, depth)):
        eps = (1 + w) * eps
        w = w * w
    return min(1.0, max(0.0, additions * eps))


def sample_ledger(params: SableParams | str, depth: int = 1, additions: int = 1, fl_clients: int = 100, model_length: int = 100) -> SampleLedger:
    if isinstance(params, str):
        params = PRESETS[params]
    n = int(params.n)
    N = n + 1
    k = int(params.k)
    m_c = int(params.m_c)
    replicas = int(params.replicas)
    expansion_rows = N * N
    compaction_rows = N * m_c
    row_diffs = N * (m_c * (m_c - 1) // 2)
    input_rows = max(0, fl_clients) * max(0, model_length) * replicas
    w0 = _fresh_support_bound(params)
    wD = _depth_support_bound(w0, depth)
    return SampleLedger(
        preset=params.name,
        q=int(params.q),
        n=n,
        N=N,
        k=k,
        eta=float(params.eta),
        n_c=int(params.n_c),
        m_c=m_c,
        eta_c=float(params.eta_c),
        replicas=replicas,
        depth=depth,
        additions=additions,
        fl_clients=fl_clients,
        model_length=model_length,
        expansion_key_rows=expansion_rows,
        expansion_sparse_entries_upper_bound=expansion_rows * (k + 2),
        compaction_key_rows=compaction_rows,
        same_entry_row_differences=row_diffs,
        input_ciphertext_rows=input_rows,
        deployment_ciphertext_values=max(0, fl_clients) * max(0, model_length),
        estimated_fresh_support=w0,
        estimated_depth_support_bound=wD,
        estimated_final_failure_bound=_failure_bound(params, depth, additions),
    )


def proof_package_manifest(preset: str = "c7_standard_toy_noisy", depth: int = 1, additions: int = 1, target_bits: int = 128, fl_clients: int = 100, model_length: int = 100) -> dict[str, Any]:
    ledger = sample_ledger(PRESETS[preset], depth=depth, additions=additions, fl_clients=fl_clients, model_length=model_length)
    return {
        "schema": SCHEMA,
        "version": __version__,
        "release_name": __release_name__,
        "target_bits": target_bits,
        "proof_info": proof_info(),
        "security_game": security_game_spec(),
        "proof_obligations": [x.to_jsonable() for x in proof_obligations()],
        "hybrid_steps": [x.to_jsonable() for x in hybrid_steps()],
        "sample_ledger": ledger.to_jsonable(),
        "review_note": "This package strengthens formal proof presentation. Concrete parameter acceptance requires external LPN/ISD/BKW cryptanalysis.",
    }


def _manifest_markdown(manifest: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# SABLE-HE Formal Proof Package")
    lines.append("")
    lines.append(f"Version: `{manifest['version']}`")
    lines.append(f"Target bits: `{manifest['target_bits']}`")
    lines.append(f"Status: `{manifest['proof_info']['status']}`")
    lines.append("")
    lines.append("## Security game")
    lines.append(manifest["security_game"]["security_claim"])
    lines.append("")
    lines.append("## Proof obligations")
    for item in manifest["proof_obligations"]:
        lines.append(f"- **{item['identifier']} ({item['category']})**: {item['statement']}")
    lines.append("")
    lines.append("## Hybrid steps")
    for step in manifest["hybrid_steps"]:
        lines.append(f"- **{step['step']} {step['name']}**: {step['replaced_distribution']} under {step['assumption']}.")
    lines.append("")
    lines.append("## Sample ledger")
    ledger = manifest["sample_ledger"]
    for key in ["preset", "q", "n", "N", "k", "expansion_key_rows", "compaction_key_rows", "same_entry_row_differences", "input_ciphertext_rows", "estimated_final_failure_bound"]:
        lines.append(f"- {key}: {ledger[key]}")
    lines.append("")
    lines.append(manifest["review_note"])
    lines.append("")
    return "\n".join(lines)


def write_proof_package(output: str | Path, preset: str = "c7_standard_toy_noisy", depth: int = 1, additions: int = 1, target_bits: int = 128, fl_clients: int = 100, model_length: int = 100, **_: Any) -> dict[str, Any]:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    manifest = proof_package_manifest(preset=preset, depth=depth, additions=additions, target_bits=target_bits, fl_clients=fl_clients, model_length=model_length)
    files = {
        "proof_package.json": manifest,
        "proof_manifest.json": manifest,
        "security_game.json": manifest["security_game"],
        "proof_obligations.json": manifest["proof_obligations"],
        "hybrid_steps.json": manifest["hybrid_steps"],
        "sample_ledger.json": manifest["sample_ledger"],
        "sample_counts.json": manifest["sample_ledger"],
    }
    written: dict[str, str] = {}
    for name, payload in files.items():
        path = out / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        written[name] = str(path)
    readme = out / "README.md"
    markdown = _manifest_markdown(manifest)
    readme.write_text(markdown, encoding="utf-8")
    written["README.md"] = str(readme)
    proof_md = out / "PROOF_PACKAGE.md"
    proof_md.write_text(markdown, encoding="utf-8")
    written["PROOF_PACKAGE.md"] = str(proof_md)
    return {"schema": SCHEMA, "version": __version__, "status": "written", "output": str(out), "files": written}

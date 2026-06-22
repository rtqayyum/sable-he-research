# Phase 4 hardened reference preparation

Phase 4 prepares SABLE-HE Research for more serious public review by adding deterministic release checks and stable engineering artifacts around the Python research implementation.

This phase does **not** turn SABLE-HE into certified production cryptography. It creates a cleaner path for downstream maintainers, external cryptanalysts, and future implementers of a hardened Rust/C/C++ core.

## Included checks

- Deterministic known-answer vectors for encrypted arithmetic, encrypted FedAvg, PQC envelope serialization, and cryptanalysis report generation.
- Public repository hygiene checks that reject private paper folders, PDFs, LaTeX build files, raw experiment folders, and generated artifacts.
- Version consistency checks across `pyproject.toml`, `VERSION`, `src/sable/version.py`, and `CITATION.cff`.
- CLI smoke commands for maintainers.
- Supply-chain documentation and GitHub workflow templates.

## CLI

```bash
sable-he hardening-info
sable-he kat-generate --output vectors/phase4
sable-he kat-verify vectors/phase4
sable-he repo-hygiene .
sable-he release-check .
```

## Public repository rule

The public repository should contain source code, tests, examples, documentation, small deterministic vectors, release notes, and workflows. It should not contain manuscript PDFs, LaTeX drafts, rendered pages, local notebooks, raw experiments, or build outputs.

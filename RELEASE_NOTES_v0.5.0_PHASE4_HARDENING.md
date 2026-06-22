# SABLE-HE Research v0.5.0 — Phase 4 hardened reference preparation

## Added

- `sable.phase4` hardening/release-engineering module.
- CLI commands: `hardening-info`, `kat-generate`, `kat-verify`, `repo-hygiene`, `release-check`.
- Deterministic known-answer vectors for arithmetic, encrypted FedAvg, PQC envelope serialization, and cryptanalysis reporting.
- Public repository hygiene and version-consistency checks.
- Phase 4 documentation under `docs/phase4/`.
- Maintainer tools under `tools/`.
- OpenSSF Scorecard workflow template.

## Scope

This release improves public review and release hygiene. It does not provide certified secure parameters, FIPS validation, side-channel certification, or a production cryptographic security boundary.

# SABLE-HE v0.11.0 — Phase 10 Compaction Theory Framework

This internal strengthening release adds a theorem-ready compaction layer model.
It formalizes public mask-family compaction, sparse mask-kernel relation
resistance, coordinate compaction as the conservative main proposal, and
block-dictionary relation warnings.

Added:

- `sable.compaction_theory` module.
- CLI commands:
  - `sable-he compaction-info`
  - `sable-he compaction-analyze`
  - `sable-he compaction-compare`
  - `sable-he compaction-theorems`
  - `sable-he compaction-package`
- Phase 10 docs under `docs/phase10/`.
- Review package generator: `tools/generate_phase10_compaction_package.py`.
- Example: `examples/compaction_theory.py`.
- Tests: `tests/test_phase10_compaction_theory.py`.

Status: internal top-venue strengthening material; not a certified security
claim and not an independent cryptanalysis result.

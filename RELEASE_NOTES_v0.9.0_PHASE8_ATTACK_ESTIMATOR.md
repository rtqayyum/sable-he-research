# SABLE-HE v0.9.0 — Phase 8 advanced attack-estimator framework

This internal release adds a stronger LPN/ISD/BKW screening framework for
reviewing SABLE-HE candidate parameter rows.

Added:

- `sable.advanced_attacks` module.
- CLI commands:
  - `sable-he attack-estimator-info`
  - `sable-he attack-estimate`
  - `sable-he attack-package`
- Public-surface models for expansion keys, compaction keys, row-difference
  CLPN surfaces, and deployment input ciphertexts.
- Clean-subset, Prange-style, Stern-style proxy, Dumer-style proxy,
  May--Ozerov-style proxy, and q-ary BKW scan outputs.
- Phase 8 docs and tests.

Status: internal screening and external-review support only.  These estimates
are not expert certification and do not make SABLE-HE production cryptography.

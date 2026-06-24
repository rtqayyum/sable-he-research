# Phase 6 build and test report

Release: `sable-he-research 0.7.0`

Added public proof-strengthening tooling:

- `src/sable/proofs.py`
- `sable-he proof-info`
- `sable-he security-game`
- `sable-he proof-obligations`
- `sable-he proof-ledger`
- `sable-he proof-package`
- `tests/test_phase6_proofs.py`

Validation performed in the build environment:

```text
pytest: pass
repo hygiene: pass
release check: pass
KAT verification: pass
proof package generation: pass
```

This report is release-engineering evidence only. It is not independent cryptanalysis and does not certify SABLE-HE parameters.
SABLE-HE formal proof package 0.7.0 (Phase 6 formal proof strengthening)
status=formal-proof-strengthening; not independent cryptanalysis or certification
Scope:
  - secret-key IND-CPA game with public evaluation keys
  - correctness obligations for compact encryption, expansion, evaluation, and compaction
  - hybrid sequence for replacing compaction key, expansion key, oracle ciphertexts, and challenge ciphertext
  - sample-count ledger for public LPN/code surfaces
Non-goals:
  - certified 128/192/256-bit parameters
  - CCA security
  - bootstrapped/full FHE
  - side-channel security
  - NIST/FIPS validation
  - independent cryptanalysis
```

## KAT verification

```text
KAT verification status=pass path=vectors/phase4
```

## Repository hygiene

```text
public repository hygiene status=fail scanned_files=284
  - error: dist/: private, generated, build, or paper artifact should not be public
  - error: dist/sable_he_research-0.7.0-py3-none-any.whl: private, generated, build, or paper artifact should not be public
  - error: dist/sable_he_research-0.7.0.tar.gz: private, generated, build, or paper artifact should not be public
```

## Release check

```text
```

This release remains proof-audit and review tooling. It is not certified production cryptography.

# Phase 2 QA audit report — v0.3.1

This release re-audits the Phase 2 post-quantum wrapper package and fixes release-quality consistency issues found in v0.3.0.

## Scope audited

- Package metadata in `pyproject.toml`, `src/sable/version.py`, and `VERSION`.
- `sable.pqc` provider interface and envelope schema.
- CLI commands: `pqc-info`, `pqc-demo`, `self-test`, and FL demo commands.
- Federated-learning update envelope helpers.
- Documentation and release notes.
- Source tests and fresh wheel smoke tests.

## Corrections made

- Synchronized all current-release version identifiers to `0.3.1`.
- Updated the release label to `Phase 2 PQC wrapper QA release`.
- Added PQC hardening tests for:
  - explicit demo-provider opt-in;
  - JSON envelope round-trip;
  - trusted sender public-key mismatch;
  - ciphertext tampering;
  - schema tampering;
  - capability-report serialization.
- Preserved the security boundary: the bundled demo provider is non-secure and test-only; production deployments must plug in reviewed ML-KEM/ML-DSA/SLH-DSA providers and validated symmetric cryptography where certification is required.

## Validation result

```text
114 passed
```

## Build artifacts

- `sable_he_research-0.3.1-py3-none-any.whl`
- `sable_he_research-0.3.1.tar.gz`

## Smoke tests

The wheel was installed into an isolated environment and checked with:

```bash
sable-he --version
sable-he pqc-info
sable-he pqc-demo
sable-he fl-demo
sable-he self-test
```

All smoke checks completed successfully.

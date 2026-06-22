# Phase 2 Build and Smoke Report

Version: `0.3.1`

## Validation

Full test suite: see `PHASE2_PYTEST_OUTPUT.txt`.

## Built artifacts

- `dist/sable_he_research-0.3.1-py3-none-any.whl`
- `dist/sable_he_research-0.3.1.tar.gz`

## Smoke commands

The wheel was installed in a fresh virtual environment and the following commands completed:

```bash
sable-he --version
sable-he pqc-info
sable-he pqc-demo
sable-he self-test
```

## Security note

`pqc-demo` uses the explicitly non-secure demo backend. For real deployments, connect `sable.pqc` to a reviewed implementation of standardized PQC primitives and to a validated symmetric cryptography module if certification is required.

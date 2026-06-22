# SABLE-HE Research v0.3.1 — Phase 2 PQC wrapper QA release

This is a QA refresh of the Phase 2 post-quantum wrapper release.

## Highlights

- Keeps the Phase 2 backend-neutral PQC envelope API.
- Keeps default labels `ML-KEM-768`, `ML-DSA-65`, `SHA3-256`, and `AES-256-GCM`.
- Keeps the optional `liboqs-python` adapter for prototyping.
- Synchronizes package version metadata across `pyproject.toml`, `src/sable/version.py`, `VERSION`, README, and Phase 2 docs.
- Adds stricter PQC-envelope hardening tests.

## Validation

```text
114 passed
```

## Security status

The package provides a research implementation and a provider-neutral envelope format. The bundled demo provider is deliberately non-secure and exists only for tests/examples. Production deployments must use reviewed providers for standardized PQC primitives and validated symmetric primitives where certification is required. SABLE-HE itself remains a research HE layer requiring independent cryptanalysis and parameter review before production security claims.

# PQC wrapper

The `sable.pqc` module defines a backend-neutral envelope format for sealing and signing SABLE-HE payloads. It uses standardized labels such as `ML-KEM-768`, `ML-DSA-65`, `SHA3-256`, and `AES-256-GCM`.

```bash
sable-he pqc-info
sable-he pqc-demo
```

The bundled demo provider is intentionally non-secure and only for examples/tests. Production deployments must use reviewed PQC and symmetric-crypto providers.

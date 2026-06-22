# PQC Backends

## Demo provider

`DemoPQCProvider` is non-secure and exists only for tests and examples. It requires explicit opt-in:

```python
from sable.pqc import DemoPQCProvider
provider = DemoPQCProvider(allow_insecure_demo=True)
```

## liboqs-python adapter

`OQSPQCProvider` dynamically imports `oqs` and uses the `KeyEncapsulation` and `Signature` classes when available. The Open Quantum Safe Python package is useful for prototyping and evaluation. Production deployments must verify the backend, version, algorithm configuration, platform hardening, side-channel posture, and compliance requirements.

## Custom provider

Applications can implement the `PQCProvider` protocol with methods:

- `kem_keypair`
- `encapsulate`
- `decapsulate`
- `signature_keypair`
- `sign`
- `verify`

This lets an organization plug in a commercial HSM, a FIPS module, or a cloud KMS once those services support the required PQC operations.

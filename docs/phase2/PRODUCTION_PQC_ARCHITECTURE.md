# Production PQC Architecture Boundary

Recommended deployment boundary:

```text
Certified / certifiable PQC boundary
  ML-KEM key establishment
  ML-DSA or SLH-DSA signatures
  AES-GCM, SHA-2/SHA-3, DRBG, KDF
        |
        v
SABLE envelope layer
  versioned JSON envelope
  signed metadata
  encrypted model-update payload
        |
        v
SABLE-HE research layer
  encrypted aggregation experiments
  sparse-LPN/code-LPN HE construction
```

This package provides the envelope layer and provider interface. A deployment that needs formal certification should source the approved algorithms from a validated cryptographic module and keep SABLE-HE as a research or non-approved service until independent cryptanalysis and standardization produce a validation path for the HE primitive itself.

## Security claims that are allowed

- The package supports a standardized-PQC envelope interface.
- The envelope can be backed by ML-KEM and ML-DSA/SLH-DSA providers.
- SABLE-HE payloads can be signed, sealed, versioned, and transported using that interface.

## Security claims that are not allowed yet

- SABLE-HE is certified production cryptography.
- The bundled Python implementation is FIPS validated.
- The demo provider provides security.
- SABLE-HE has certified 128-bit security parameters.

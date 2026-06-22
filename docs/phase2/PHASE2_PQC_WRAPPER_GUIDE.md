# Phase 2: Production PQC Wrapper Guide

Phase 2 adds a backend-neutral post-quantum envelope layer around SABLE-HE payloads. The goal is to place SABLE-HE research payloads inside a conventional PQC security boundary based on standardized primitives:

- **ML-KEM** for key establishment / encapsulation.
- **ML-DSA** for digital signatures.
- **SLH-DSA** as a conservative hash-based signature option where appropriate.
- **AES-GCM** plus SHA-3/HKDF-style derivation for payload confidentiality and integrity.

The wrapper lives in `sable.pqc`. It does not turn SABLE-HE itself into a certified cryptographic primitive. Instead, it gives production engineers a clean interface for protecting SABLE-HE model-update payloads with standardized PQC components.

## Basic API

```python
from sable import pqc

provider = pqc.get_provider("demo", allow_insecure_demo=True)  # examples/tests only
recipient = provider.kem_keypair("ML-KEM-768")
signer = provider.signature_keypair("ML-DSA-65")

payload = {"weights": [0.158, -0.366, 1.155]}

envelope = pqc.make_signed_federated_update_envelope(
    payload,
    sample_count=200,
    round_id="round-0001",
    client_id="client-A",
    recipient_kem_public_key=recipient.public_key,
    sender_signature_secret_key=signer.secret_key,
    sender_signature_public_key=signer.public_key,
    provider=provider,
)

opened, metadata = pqc.open_federated_update_envelope(
    envelope,
    recipient_kem_secret_key=recipient.secret_key,
    trusted_sender_signature_public_key=signer.public_key,
    provider=provider,
)
```

## CLI

```bash
sable-he pqc-info
sable-he pqc-demo
sable-he pqc-demo --json
```

The built-in demo provider is deliberately non-secure. It exists so the envelope format, CLI, tests, and documentation can run everywhere without a local PQC installation.

## Real backend path

The wrapper includes an optional `OQSPQCProvider` adapter for `liboqs-python`:

```bash
python -m pip install "sable-he-research[pqc-oqs]"
```

Then:

```python
from sable.pqc import OQSPQCProvider
provider = OQSPQCProvider()
```

For production, pin backend versions, use only standardized mechanisms, and run your own compliance and side-channel review.

"""PQC envelope demo for SABLE-HE Phase 2.

Uses the non-secure demo provider so it runs everywhere. Replace the provider
with a reviewed ML-KEM/ML-DSA implementation for real deployments.
"""

from sable import pqc

provider = pqc.get_provider("demo", allow_insecure_demo=True)
recipient = provider.kem_keypair("ML-KEM-768")
signer = provider.signature_keypair("ML-DSA-65")

payload = {"weights": [0.158, -0.366, 1.155], "kind": "fedavg-result"}

envelope = pqc.make_signed_federated_update_envelope(
    payload,
    sample_count=200,
    round_id="round-0001",
    client_id="client-demo",
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

print("opened:", opened)
print("metadata:", metadata)
print("envelope schema:", envelope.schema)

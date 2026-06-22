from sable import pqc

provider = pqc.get_provider("demo", allow_insecure_demo=True)
recipient = provider.kem_keypair("ML-KEM-768")
signer = provider.signature_keypair("ML-DSA-65")

envelope = pqc.make_signed_federated_update_envelope(
    {"weights": [0.158, -0.366, 1.155]},
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
    provider=provider,
    trusted_sender_signature_public_key=signer.public_key,
)
print(opened)
print(metadata["sample_count"])

"""Encrypted FedAvg result sealed in a SABLE PQC envelope."""

from sable import PRESETS, keygen_sable, pqc
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_sable(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000, seed=9000)

client_weights = [[0.12, -0.34, 1.20], [0.10, -0.30, 1.25], [0.20, -0.40, 1.10]]
sample_counts = [80, 20, 100]
encrypted_clients = [agg.encrypt_model(w, seed=1000 + i) for i, w in enumerate(client_weights)]
server_result = agg.fedavg(encrypted_clients, sample_counts)
final_weights = agg.decrypt_model(server_result)

provider = pqc.get_provider("demo", allow_insecure_demo=True)
recipient = provider.kem_keypair()
signer = provider.signature_keypair()

envelope = pqc.make_signed_federated_update_envelope(
    {"final_weights": final_weights},
    sample_count=sum(sample_counts),
    round_id="round-0001",
    client_id="server-aggregator",
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
print(metadata)

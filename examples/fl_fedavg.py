"""Encrypted FedAvg example for SABLE-HE."""

from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator, PlainFLAggregator


params = PRESETS["fl_demo_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000, seed=9000)

client_weights = [
    [0.12, -0.34, 1.20],
    [0.10, -0.30, 1.25],
    [0.20, -0.40, 1.10],
]
sample_counts = [80, 20, 100]

encrypted_clients = [agg.encrypt_model(weights, seed=1000 + i) for i, weights in enumerate(client_weights)]
server_result = agg.fedavg(encrypted_clients, sample_counts)
final_weights = agg.decrypt_model(server_result)
reference = PlainFLAggregator().fedavg(client_weights, sample_counts)

print("Encrypted FedAvg result:", final_weights)
print("Plaintext reference:    ", reference)

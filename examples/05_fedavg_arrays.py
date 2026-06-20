"""Encrypted FedAvg for simple model-weight arrays."""

from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo"]
kp = keygen_c7(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000, seed=5000)

client_models = [
    [0.12, -0.34, 1.20],
    [0.10, -0.30, 1.25],
    [0.20, -0.40, 1.10],
]
sample_counts = [80, 20, 100]

encrypted = [agg.encrypt_model(w, seed=1000 + i) for i, w in enumerate(client_models)]
encrypted_avg = agg.fedavg(encrypted, sample_counts)

print(agg.decrypt_model(encrypted_avg))

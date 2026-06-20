"""Encrypted FedAvg over a nested model-weight dictionary."""

from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo"]
kp = keygen_c7(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000, seed=7000)

client_a = {"dense": {"kernel": [[0.1, 0.2], [0.3, 0.4]], "bias": [0.01, -0.01]}}
client_b = {"dense": {"kernel": [[0.2, 0.1], [0.4, 0.3]], "bias": [0.02, -0.02]}}

enc_a = agg.encrypt_model(client_a, seed=1)
enc_b = agg.encrypt_model(client_b, seed=2)
enc_avg = agg.fedavg([enc_a, enc_b], [10, 30])

print(agg.decrypt_model(enc_avg))

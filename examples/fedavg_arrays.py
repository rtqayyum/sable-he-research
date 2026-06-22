from sable import PRESETS, keygen_sable
from sable.fl import EncryptedFLAggregator, PlainFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_sable(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000, seed=9000)

client_weights = [
    [0.12, -0.34, 1.20],
    [0.10, -0.30, 1.25],
    [0.20, -0.40, 1.10],
]
sample_counts = [80, 20, 100]

encrypted = [agg.encrypt_model(w, seed=1000+i) for i, w in enumerate(client_weights)]
enc_avg = agg.fedavg(encrypted, sample_counts)
print(agg.decrypt_model(enc_avg))
print(PlainFLAggregator().fedavg(client_weights, sample_counts))

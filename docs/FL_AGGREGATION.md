# Federated-learning aggregation

Encrypted-native aggregation supports additive methods such as sum, mean, weighted mean, FedAvg, and FedSGD.

```python
from sable import PRESETS, keygen_sable
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_sable(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000)

models = [[0.1, 0.2], [0.3, 0.4]]
counts = [10, 30]
enc = [agg.encrypt_model(m, seed=100+i) for i, m in enumerate(models)]
enc_avg = agg.fedavg(enc, counts)
print(agg.decrypt_model(enc_avg))
```

Robust methods such as median, min, max, trimmed mean, Krum, and Multi-Krum require comparison/sorting/distance operations, so they are exposed as plaintext or decrypt-side operations.

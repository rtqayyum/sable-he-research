# FL aggregation API

SABLE-HE v0.2.0 exposes the federated-learning API through `sable.fl`.

```python
from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator

kp = keygen_c7(PRESETS["fl_demo"], seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000)

clients = [[0.12, -0.34, 1.20], [0.10, -0.30, 1.25], [0.20, -0.40, 1.10]]
counts = [80, 20, 100]

encrypted = [agg.encrypt_model(c, seed=i) for i, c in enumerate(clients)]
enc_avg = agg.fedavg(encrypted, counts)
print(agg.decrypt_model(enc_avg))
```

Encrypted-native methods:

```text
sum, mean, weighted_sum, weighted_average, fedavg, fedsgd
```

Plain/decrypt-side methods:

```text
coordinate_min, coordinate_max, coordinate_median, trimmed_mean,
norm_clipped_mean, geometric_median, krum, multi_krum
```

CLI:

```bash
sable-he fl-demo
sable-he fl-methods
```

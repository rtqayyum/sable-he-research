# Federated-learning aggregation guide

SABLE-HE provides a high-level `sable.fl` module for federated-learning aggregation.

## Core idea

For standard FedAvg, the server computes

```text
sum_i n_i * Enc(w_i)
```

where `n_i` is the public sample count for client `i` and `w_i` is the fixed-point encoded model-weight tensor. The decryptor decodes with divisor

```text
sum_i n_i
```

This avoids modular inverse surprises and gives ordinary fixed-point averages.

## Main classes

```python
from sable.fl import EncryptedFLAggregator, PlainFLAggregator
```

`EncryptedFLAggregator` encrypts tensors/model weights, performs encrypted linear aggregation, and decrypts the result when the key holder is present.

`PlainFLAggregator` provides reference and robust aggregation methods on Python/NumPy/TensorFlow/Keras/Torch objects.

## Encrypted FedAvg

```python
from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000)

clients = [
    [0.12, -0.34, 1.20],
    [0.10, -0.30, 1.25],
    [0.20, -0.40, 1.10],
]
counts = [80, 20, 100]

encrypted = [agg.encrypt_model(c, seed=1000+i) for i, c in enumerate(clients)]
server_result = agg.fedavg(encrypted, counts)
final = agg.decrypt_model(server_result)
```

## Functional API

```python
from sable.fl import encrypt_array, fedavg_encrypted, decrypt_array

encrypted = [encrypt_array(kp, c, scale=1000, seed=10+i) for i, c in enumerate(clients)]
server_result = fedavg_encrypted(kp, encrypted, counts)
final = decrypt_array(kp, server_result)
```

## NumPy arrays

```python
import numpy as np

client_a = np.array([0.12, -0.34, 1.20])
client_b = np.array([0.10, -0.30, 1.25])

enc_a = agg.encrypt_model(client_a, seed=1)
enc_b = agg.encrypt_model(client_b, seed=2)
mean = agg.mean([enc_a, enc_b])
out = agg.decrypt_model(mean)
```

If NumPy is installed, restored arrays come back as NumPy arrays.

## Keras model weights

```python
weights_a = model_a.get_weights()
weights_b = model_b.get_weights()

enc_a = agg.encrypt_model(weights_a, seed=1)
enc_b = agg.encrypt_model(weights_b, seed=2)

enc_global = agg.fedavg([enc_a, enc_b], [len_a, len_b])
global_weights = agg.decrypt_model(enc_global)
model_global.set_weights(global_weights)
```

You can also pass a Keras model directly if it exposes `get_weights()`.

## Supported encrypted-native methods

| Method | API | Notes |
|---|---|---|
| Sum | `agg.sum(models)` | Elementwise encrypted addition |
| Mean | `agg.mean(models)` | Sum plus decode divisor |
| Weighted sum | `agg.weighted_sum(models, weights)` | Public integer/fixed-point weights |
| Weighted average | `agg.weighted_average(models, weights)` | Weighted sum plus divisor |
| FedAvg | `agg.fedavg(models, sample_counts)` | Sample-count weighted average |
| FedSGD | `agg.fedsgd(gradients, sample_counts)` | Same primitive on gradients |

## Robust/ordering methods

These methods are available through `PlainFLAggregator` or after decryptor-side decryption:

```python
plain = PlainFLAggregator()
plain.coordinate_min(models)
plain.coordinate_max(models)
plain.coordinate_median(models)
plain.trimmed_mean(models, trim_ratio=0.1)
plain.norm_clipped_mean(models, clip_norm=10.0)
plain.geometric_median(models)
plain.krum(models, f=1)
plain.multi_krum(models, f=1, m=3)
```

Encrypted min/max/median/trimmed/Krum are deliberately not silent aliases because these methods require comparison, sorting, norm computation, or distance ranking. Calling `agg.min(...)` or `sable.fl.min_encrypted(...)` raises `EncryptedComparisonNotSupported`.

## Fixed-point scaling

Choose `scale` according to the precision you want:

```text
scale=100        two decimal places
scale=1000       three decimal places
scale=1000000    six decimal places
```

The modulus `q` must be large enough for:

```text
max_abs_weight * scale * total_weight
```

to fit inside the signed field range without wraparound.

## Practical note

The current public Python package encrypts each scalar weight separately. That is useful for correctness, API, and research validation. Large production FL workloads need batching/packing and externally reviewed parameter sets.

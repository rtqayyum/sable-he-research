# Federated-learning aggregation guide

SABLE-HE v0.2.0 adds a federated-learning layer in `sable.fl`.

The encrypted backend supports additive aggregation:

- `sum`
- `mean`
- `weighted_sum`
- `weighted_average` / `weighted_mean`
- `fedavg`
- `fedsgd`-style weighted gradient averaging

These operations are homomorphic because they need only encrypted addition and public scalar multiplication.

Ordering- or distance-based methods are available as plaintext/decrypt-side helpers:

- coordinate min
- coordinate max
- coordinate median
- trimmed mean
- norm-clipped mean
- geometric median
- Krum
- Multi-Krum

They are not exposed as encrypted-native operations because they require comparison, sorting, norms, or pairwise distances.

## Encrypted FedAvg for arrays

```python
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

result = agg.decrypt_model(encrypted_avg)
print(result)  # [0.158, -0.366, 1.155]
```

## Functional API

```python
from sable import PRESETS, keygen_c7
from sable import fl

kp = keygen_c7(PRESETS["fl_demo"], seed=123, mode="coordinate")

clients = [[0.1, 0.2], [0.3, 0.4]]
counts = [10, 30]

encrypted = [fl.encrypt_array(kp, x, scale=1000, seed=i) for i, x in enumerate(clients)]
enc_avg = fl.fedavg_encrypted(kp, encrypted, counts)
result = fl.decrypt_array(kp, enc_avg)
```

## Fixed-point encoding

Model weights are encoded as:

```text
round(weight * scale) mod q
```

The decryptor decodes using signed modular representation and divides by `scale * divisor`.

For FedAvg, the server computes:

```text
sum_i sample_count_i * Enc(weights_i)
```

The encrypted result stores `sum_i sample_count_i` as divisor metadata. Division happens during decryption in normal floating-point arithmetic.

## Avoiding modular wraparound

Choose `q` so that:

```text
2 * max_abs_weight * scale * sum(sample_counts) < q
```

A helper is available:

```python
from sable.fl import estimate_encoded_bound

q_needed = estimate_encoded_bound(1.25, scale=1000, max_weight_sum=200)
```

## Tensor/model support

The adapter supports:

- Python scalars/lists/tuples/dictionaries
- NumPy arrays
- TensorFlow eager tensors
- Keras models or Keras `get_weights()` lists
- PyTorch tensors, when PyTorch is installed

TensorFlow, Keras, and PyTorch are optional dependencies. The base package does not require installing them.

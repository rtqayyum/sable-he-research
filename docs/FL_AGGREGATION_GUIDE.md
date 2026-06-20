# Federated-learning aggregation with SABLE-HE

SABLE-HE v0.2 adds `sable.fl`, a federated-learning aggregation layer for model weights, gradients, NumPy arrays, nested Python structures, Torch tensors, TensorFlow-style tensors, and Keras-style model weight lists.

The core encrypted FL use case is **FedAvg**:

\[
\operatorname{FedAvg}(w_1,\ldots,w_m)=\frac{\sum_i n_i w_i}{\sum_i n_i},
\]

where `n_i` is each client's sample count. The server can compute the encrypted weighted numerator with homomorphic addition and public scalar multiplication. The decryptor then divides by the public sample-count sum after decryption.

## Installation

```bash
python -m pip install sable_he_research-0.2.0-py3-none-any.whl
```

Optional NumPy adapter support:

```bash
python -m pip install "sable-he-research[numpy]"
```

## Encrypted FedAvg over arrays

```python
from sable import PRESETS
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
agg = EncryptedFLAggregator.from_params(params, key_seed=123, scale=1000)

client_weights = [
    [0.12, -0.34, 1.20],
    [0.10, -0.30, 1.25],
    [0.20, -0.40, 1.10],
]
sample_counts = [80, 20, 100]

encrypted = [agg.encrypt_model(weights, seed=10_000 + i) for i, weights in enumerate(client_weights)]
encrypted_global = agg.fedavg(encrypted, sample_counts)

global_weights = agg.decrypt_model(encrypted_global)
print(global_weights)
# [0.158, -0.366, 1.155]
```

## Native encrypted aggregations

These methods operate on encrypted tensors without exposing model values to the aggregation server:

```python
agg.sum(encrypted_models)
agg.mean(encrypted_models)
agg.weighted_sum(encrypted_models, weights)
agg.weighted_average(encrypted_models, weights)
agg.fedavg(encrypted_models, sample_counts)
```

The native encrypted methods are linear. They use encrypted addition and public scalar multiplication.

## Plain/tensor robust aggregations

Some FL aggregations require ordering, comparison, distances, or sorting. SABLE-HE includes these as tensor-aware plaintext utilities:

```python
from sable.fl import PlainFLAggregator

plain = PlainFLAggregator()
plain.coordinate_min(models)
plain.coordinate_max(models)
plain.coordinate_median(models)
plain.trimmed_mean(models, trim_ratio=0.2)
plain.geometric_median(models)
plain.krum(models, f=1)
plain.multi_krum(models, f=1, m=3)
plain.norm_clipped_mean(models, clip_norm=10.0)
```

Encrypted min, max, median, Krum, and trimmed mean require comparison/sorting/distance circuits. The current package exposes clear errors for encrypted versions rather than silently decrypting or leaking values.

## Capability matrix

```python
from sable.fl import fl_capabilities

for cap in fl_capabilities():
    print(cap.method, cap.encrypted_native, cap.plaintext_tensor, cap.notes)
```

CLI:

```bash
sable-he fl-capabilities
```

## NumPy, TensorFlow, Keras, and PyTorch adapters

`sable.fl` accepts:

- Python scalars;
- flat or nested lists/tuples;
- dictionaries of arrays/layers;
- NumPy arrays;
- PyTorch tensors through `detach().cpu().numpy()`;
- TensorFlow-style tensors through `.numpy()`;
- Keras-style models or objects with `get_weights()`.

For Keras-style models, encryption reads `model.get_weights()`. After decryption, assign the aggregated weights back with:

```python
from sable.fl import assign_model_weights

assign_model_weights(model, global_weights)
```

## Fixed-point encoding

Model weights are real numbers, while SABLE operates over a finite field. The FL API uses signed fixed-point encoding:

```text
encoded = round(value * scale) mod q
```

Choose `q` large enough to avoid wraparound after weighted summation. For FedAvg with maximum absolute weight `B`, fixed-point scale `S`, and total sample count `N`, a conservative condition is:

```text
q > 2 * B * S * N
```

Use a larger margin in experiments.

## CLI demo

```bash
sable-he fl-demo
sable-he fl-demo --json
```

## Security status

The FL API is suitable for package-level experimentation, protocol simulation, documentation, and research benchmarking. It is not a certified secure FL deployment stack. A real deployment requires reviewed parameters, authentication, secure key management, audited serialization, side-channel review, transport security, client authentication, and independent cryptanalysis.

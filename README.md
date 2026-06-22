# SABLE-HE (Post Quantum Homomorphic Encryption)

SABLE-HE is a Python research-preview package for code/LPN-based homomorphic arithmetic and federated-learning aggregation experiments.

The package includes:

- C7 relation-resistant compaction APIs for SABLE-HE experiments;
- arithmetic operations over the native prime-field message space;
- encrypted FL aggregation helpers for `sum`, `mean`, `weighted_sum`, `weighted_average`, `FedAvg`, and `FedSGD`;
- plaintext/decryptor-side robust FL aggregation helpers for coordinate min/max, median, trimmed mean, geometric median, norm-clipped mean, Krum, and Multi-Krum;
- adapters for Python lists, NumPy arrays, TensorFlow tensors, Keras `get_weights()` lists/models, and Torch tensors when those optional libraries are installed;
- CLI demos, estimators, tests, and documentation.

> Security note: this package is a research-preview implementation. It does not ship externally certified security parameters. Use it for research, education, validation, and reproducible experiments unless and until your chosen parameter sets and implementation have been independently reviewed.

## Install

From a local wheel:

```bash
python -m pip install dist/sable_he_research-0.2.0-py3-none-any.whl
```

From source:

```bash
python -m pip install .
```

With NumPy adapters:

```bash
python -m pip install .[numpy]
```

For local development:

```bash
python -m pip install -e .[dev,numpy]
python -m pytest -q
```

For pip:

```bash
python -m pip install sable-he-research
```

## Quick encrypted FedAvg example

```python
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

encrypted_clients = [
    agg.encrypt_model(weights, seed=1000 + i)
    for i, weights in enumerate(client_weights)
]

server_result = agg.fedavg(encrypted_clients, sample_counts)
final_weights = agg.decrypt_model(server_result)

print(final_weights)  # [0.158, -0.366, 1.155]

reference = PlainFLAggregator().fedavg(client_weights, sample_counts)
print(reference)
```

## NumPy / Keras-style model weights

```python
import numpy as np
from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000)

client_a = [np.array([1.0, 2.0]), np.array([[3.0], [4.0]])]
client_b = [np.array([2.0, 4.0]), np.array([[6.0], [8.0]])]

enc_a = agg.encrypt_model(client_a, seed=11)
enc_b = agg.encrypt_model(client_b, seed=22)

enc_avg = agg.fedavg([enc_a, enc_b], [1, 3])
weights = agg.decrypt_model(enc_avg)

print(weights[0])  # [1.75, 3.50]
print(weights[1])  # [[5.25], [7.00]]
```

For a Keras model, pass either `model.get_weights()` or the model itself to `encrypt_model`. To put decrypted weights back into a model, call `model.set_weights(weights)` or use `sable.fl.assign_model_weights(model, weights)`.

## CLI

```bash
sable-he --version
sable-he fl-capabilities
sable-he fl-demo --json
sable-he demo --operation add --x 12 --y 20
sable-he estimate --preset fl_demo_clean --depth 1
sable-he readiness
```

## FL method support

Encrypted-native methods:

- `sum`
- `mean`
- `weighted_sum`
- `weighted_average`
- `fedavg`
- `fedsgd`

Plain/decryptor-side methods:

- `coordinate_min`
- `coordinate_max`
- `coordinate_median`
- `trimmed_mean`
- `norm_clipped_mean`
- `geometric_median`
- `krum`
- `multi_krum`

Min/max/median/trimmed/Krum need comparison, sorting, norms, or pairwise distances. They are therefore available as plaintext tensor operations or after decryptor-side decryption, not as silent encrypted operations.

## Documentation

Start here:

- `docs/FL_AGGREGATION.md` — detailed encrypted FedAvg and FL aggregation guide.
- `docs/API_REFERENCE.md` — API overview.
- `docs/CLI_REFERENCE.md` — command-line usage.
- `docs/GITHUB_PYPI_RELEASE_GUIDE.md` — how to publish to GitHub and PyPI.
- `SECURITY.md` — security status and reporting policy.

## Repository layout

```text
src/sable/          package source
tests/              pytest suite
examples/           runnable examples
docs/               user and release documentation
benchmarks/         benchmark/proxy scripts
```

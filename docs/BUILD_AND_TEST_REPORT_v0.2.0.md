# Build and test report — SABLE-HE v0.2.0

## Added in this release

- `sable.fl` federated-learning API.
- Encrypted-native aggregation: sum, mean, weighted sum, weighted average, FedAvg, FedSGD-style averaging.
- Plain/tensor robust aggregation: coordinate min/max, median, trimmed mean, norm-clipped mean, geometric median, Krum, Multi-Krum.
- Tensor adapters for lists, tuples, dictionaries, NumPy arrays, PyTorch tensors, TensorFlow-style tensors, and Keras-style model weights.
- CLI commands: `fl-demo`, `fl-capabilities`, and `fl-methods`.
- Public release documentation for GitHub and PyPI.

## Local validation

```text
pytest -q
104 passed
```

## Wheel smoke test

A fresh virtual environment successfully installed the local wheel and ran:

```bash
sable-he --version
sable-he fl-capabilities
sable-he fl-demo --json
```

The encrypted FedAvg result matched the plaintext reference for the included three-client model-weight example.

## Built artifacts

```text
dist/sable_he_research-0.2.0-py3-none-any.whl
dist/sable_he_research-0.2.0.tar.gz
```

## Scope note

The package is suitable for open-source research, protocol simulation, examples, and reproducible package-level validation. It is not independently audited production cryptography and does not provide certified security parameters.

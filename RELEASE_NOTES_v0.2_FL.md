# SABLE-HE v0.2.0 — Federated-learning aggregation API

## Added

- `sable.fl` public FL aggregation module.
- Encrypted-native FL methods:
  - sum
  - mean
  - weighted sum
  - weighted average
  - FedAvg
  - FedSGD
- Plain/decryptor-side robust FL methods:
  - coordinate min
  - coordinate max
  - coordinate median
  - trimmed mean
  - norm-clipped mean
  - geometric median
  - Krum
  - Multi-Krum
- Python list, NumPy, TensorFlow, Keras, and Torch tensor/model adapters.
- CLI commands:
  - `sable-he fl-demo`
  - `sable-he fl-capabilities`
  - `sable-he fl-methods`
- `fl_demo_clean` preset for reproducible fixed-point FL examples.
- Detailed FL and GitHub/PyPI release documentation.

## Notes

- Encrypted min/max/median/trimmed/Krum are not advertised as native encrypted operations because they require comparison/sorting/distance circuits.
- The package remains a research-preview implementation without externally certified security parameters.

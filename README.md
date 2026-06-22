# SABLE-HE Research

[![PyPI](https://img.shields.io/pypi/v/sable-he-research.svg)](https://pypi.org/project/sable-he-research/)
[![Python](https://img.shields.io/pypi/pyversions/sable-he-research.svg)](https://pypi.org/project/sable-he-research/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SABLE-HE Research is a clean public research implementation of **SABLE-HE**, a post-quantum code/LPN-based leveled homomorphic-encryption toolkit for low-degree encrypted arithmetic, encrypted federated aggregation, PQC envelope integration, and independent cryptanalysis review.

This repository intentionally excludes private working artifacts such as LaTeX paper folders, PDFs, generated experiment logs, rendered pages, local notebooks, and old internal build debris.

## Status

SABLE-HE Research is suitable for research experiments, API exploration, encrypted FedAvg-style aggregation demos, and independent cryptanalysis. It is **not** a certified cryptographic module and does not ship certified secure parameter sets. Read [`SECURITY.md`](SECURITY.md) before using the package.

## Install

```bash
python -m pip install sable-he-research
```

From source:

```bash
git clone https://github.com/rtqayyum/sable-he-research.git
cd sable-he-research
python -m pip install -e ".[dev,numpy]"
python -m pytest -q
```

## Quick encrypted FedAvg example

```python
from sable import PRESETS, keygen_sable
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_sable(params, seed=123, mode="coordinate")
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
```

## CLI

```bash
sable-he --version
sable-he fl-demo
sable-he pqc-info
sable-he cryptanalysis-info
sable-he cryptanalysis-bundle --output review_bundle
sable-he hardening-info
sable-he kat-verify vectors/phase4
sable-he release-check .
sable-he self-test
```

## Main modules

- `sable.operations`: encrypted arithmetic and Boolean-gate helpers.
- `sable.fl`: encrypted and plaintext/decrypt-side federated aggregation utilities.
- `sable.pqc`: backend-neutral PQC envelope format and provider interface.
- `sable.cryptanalysis`: public attack-surface reports and review bundles.
- `sable.phase4`: KATs, public repo hygiene, and release-engineering checks.

## Documentation

- [`docs/INSTALLATION.md`](docs/INSTALLATION.md)
- [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
- [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)
- [`docs/FL_AGGREGATION.md`](docs/FL_AGGREGATION.md)
- [`docs/PQC_WRAPPER.md`](docs/PQC_WRAPPER.md)
- [`docs/CRYPTANALYSIS_REVIEW.md`](docs/CRYPTANALYSIS_REVIEW.md)
- [`docs/SECURITY_SCOPE.md`](docs/SECURITY_SCOPE.md)
- [`docs/PUBLIC_REPO_MANIFEST.md`](docs/PUBLIC_REPO_MANIFEST.md)
- [`docs/phase4/PHASE4_HARDENING_GUIDE.md`](docs/phase4/PHASE4_HARDENING_GUIDE.md)

## What is intentionally not in this public repository

- LaTeX manuscript folders and paper PDFs.
- Rendered paper pages and figure-generation scratch folders.
- Private notes, unpublished drafts, and local notebooks.
- Generated experiment logs and large generated CSV/JSON dumps.
- Old distribution files and local build outputs.
- API tokens, keys, secrets, or deployment credentials.

## Citation

Use [`CITATION.cff`](CITATION.cff) or [`docs/CITATION.md`](docs/CITATION.md).

## License

MIT License. See [`LICENSE`](LICENSE).

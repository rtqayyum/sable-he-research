# SABLE-HE Research

[![PyPI](https://img.shields.io/pypi/v/sable-he-research.svg)](https://pypi.org/project/sable-he-research/)
[![Python](https://img.shields.io/pypi/pyversions/sable-he-research.svg)](https://pypi.org/project/sable-he-research/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SABLE-HE Research is a public research implementation of **SABLE-HE**, a post-quantum code/LPN-based leveled homomorphic-encryption toolkit for low-degree encrypted arithmetic and federated-learning aggregation experiments.

The project focuses on **post-quantum code-based homomorphic encryption**. It uses sparse q-ary LPN-style encryption for compact inputs and nonlinear homomorphic evaluation, and q-ary code/LPN encryption for relation-resistant coordinate compaction. The federated-learning layer exposes encrypted additive aggregation such as FedAvg and weighted averaging, together with tensor adapters for common Python ML objects.

## Current scope

SABLE-HE Research is suitable for:

- research experiments in code/LPN-based homomorphic encryption;
- encrypted additive aggregation experiments for federated learning;
- reproducible validation of low-degree arithmetic over prime fields;
- comparison studies against established HE families;
- cryptanalysis, parameter-estimation, and implementation-review work.

SABLE-HE Research is **not** a certified cryptographic module and does not ship certified security parameters. See [`SECURITY.md`](SECURITY.md) before using the package.

## Install

From PyPI:

```bash
python -m pip install sable-he-research
```

With NumPy adapters:

```bash
python -m pip install "sable-he-research[numpy]"
```

From source:

```bash
git clone https://github.com/rtqayyum/sable-he-research.git
cd sable-he-research
python -m pip install -e ".[dev,numpy]"
python -m pytest -q
```


## Phase 2: standardized PQC wrapper

Version 0.4.0 adds a backend-neutral post-quantum envelope layer under `sable.pqc`. The wrapper is designed to seal and sign SABLE-HE payloads, including federated-learning model updates, using standardized post-quantum primitives such as ML-KEM for key establishment and ML-DSA/SLH-DSA-style signatures when connected to a reviewed provider.

```bash
sable-he pqc-info
sable-he pqc-demo
```

Python example:

```python
from sable import pqc

provider = pqc.get_provider("demo", allow_insecure_demo=True)  # non-secure examples only
recipient = provider.kem_keypair("ML-KEM-768")
signer = provider.signature_keypair("ML-DSA-65")

envelope = pqc.make_signed_federated_update_envelope(
    {"weights": [0.158, -0.366, 1.155]},
    sample_count=200,
    round_id="round-0001",
    client_id="client-demo",
    recipient_kem_public_key=recipient.public_key,
    sender_signature_secret_key=signer.secret_key,
    sender_signature_public_key=signer.public_key,
    provider=provider,
)
```

The bundled demo provider is not secure. Production deployments must plug in reviewed implementations of standardized PQC algorithms and keep SABLE-HE itself clearly labeled as the HE research layer until independent cryptanalysis and certification paths exist. See `docs/phase2/`.

## Quick encrypted FedAvg example

```python
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

encrypted_clients = [
    agg.encrypt_model(weights, seed=1000 + i)
    for i, weights in enumerate(client_weights)
]

server_result = agg.fedavg(encrypted_clients, sample_counts)
final_weights = agg.decrypt_model(server_result)

print(final_weights)  # [0.158, -0.366, 1.155]
print(PlainFLAggregator().fedavg(client_weights, sample_counts))
```

## NumPy / Keras-style model weights

```python
import numpy as np
from sable import PRESETS, keygen_sable
from sable.fl import EncryptedFLAggregator

params = PRESETS["fl_demo_clean"]
kp = keygen_sable(params, seed=123, mode="coordinate")
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

## Supported aggregation methods

Encrypted-native methods:

- `sum`
- `mean`
- `weighted_sum`
- `weighted_average`
- `fedavg`
- `fedsgd`

Plain/decryptor-side robust methods:

- `coordinate_min`
- `coordinate_max`
- `coordinate_median`
- `trimmed_mean`
- `norm_clipped_mean`
- `geometric_median`
- `krum`
- `multi_krum`

Min, max, median, trimmed mean, Krum, and Multi-Krum require comparisons, sorting, norms, or pairwise distances. They are therefore available as plaintext tensor operations or decryptor-side operations, not as hidden encrypted operations.

## Documentation

Start here:

- [`docs/PUBLIC_RESEARCH_RELEASE.md`](docs/PUBLIC_RESEARCH_RELEASE.md) - public release status and scope.
- [`docs/FL_AGGREGATION.md`](docs/FL_AGGREGATION.md) - encrypted FedAvg and FL aggregation guide.
- [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) - API overview.
- [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) - command-line usage.
- [`docs/CRYPTANALYSIS_CHALLENGE.md`](docs/CRYPTANALYSIS_CHALLENGE.md) - how to review or attack the construction.
- [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) - GitHub/PyPI release checklist.
- [`SECURITY.md`](SECURITY.md) - security status and vulnerability reporting policy.

## Repository layout

```text
src/sable/          package source
tests/              pytest suite
examples/           runnable examples
docs/               user, release, and cryptanalysis documentation
benchmarks/         benchmark/proxy scripts
.github/            CI, publishing, and issue templates
```

## Citation

Use [`CITATION.cff`](CITATION.cff) or the BibTeX entry in [`docs/CITATION.md`](docs/CITATION.md).

## License

MIT License. See [`LICENSE`](LICENSE).

## Phase 3 independent cryptanalysis package

Version 0.4.0 adds a reproducible independent-review bundle for SABLE-HE cryptanalysis. It reports public sparse-LPN and q-ary-LPN/code sample surfaces, first-pass attack screens, relation-screen output, and reviewer questions.

```bash
sable-he cryptanalysis-info --preset c7_standard_toy_noisy
sable-he cryptanalysis-bundle --preset c7_standard_toy_noisy --output-dir review_bundle
```

The cryptanalysis package is a review aid, not a certification mechanism. Passing the bundled screens does not certify parameter security.

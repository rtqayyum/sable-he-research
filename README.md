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


## Phase 5 external review and pre-standardization tooling

SABLE-HE v0.6.0 added public tooling for external cryptanalysis and pre-standardization discussion:

```bash
sable-he standardization-info
sable-he standardization-readiness
sable-he assumptions-spec
sable-he parameter-template --json
sable-he review-checklist
sable-he review-package --output sable_phase5_review_package
```

These commands do not certify SABLE-HE. They generate review materials for independent cryptanalysis and community discussion.


## Formal proof package

Version 0.8.0 adds reviewer-facing proof tooling:

```bash
sable-he proof-info
sable-he security-game
sable-he proof-obligations
sable-he proof-ledger --preset c7_standard_toy_noisy
sable-he proof-package --output sable_proof_package
```

These commands generate a proof-obligation ledger, hybrid-argument map, sample-count accounting, and reviewer questions. They support manuscript preparation and external cryptographic review; they do not certify SABLE-HE parameters.


## Phase 6 formal proof package

SABLE-HE v0.8.0 adds formal proof-strengthening commands:

```bash
sable-he proof-info
sable-he security-game
sable-he proof-obligations
sable-he proof-ledger --preset c7_standard_toy_noisy
sable-he proof-package --output sable_proof_package
```

These commands generate proof-audit artifacts for external review. They do not certify concrete parameters and do not replace independent cryptanalysis.

## Phase 7 candidate parameter framework

Version 0.8.0 adds internal working tools for category-I/III/V-style candidate parameter discussions:

```bash
sable-he parameter-framework-info
sable-he candidate-parameters
sable-he parameter-screen
sable-he parameter-package --output sable_phase7_parameter_package
```

These candidates are for external cryptanalysis and manuscript strengthening only.  They are not certified secure parameter sets and should not be used as deployment parameters.


## Phase 8 internal estimator strengthening

SABLE-HE v0.10.0 adds a stronger internal LPN/ISD/BKW estimator layer for candidate parameter review:

```bash
sable-he lpn-estimator-info
sable-he lpn-estimate --candidate sable_cat1_depth1_review
sable-he lpn-estimator-package --output sable_phase8_lpn_estimator_package
```

The estimator reports clean-subset, Prange, Lee-Brickell, Stern/Dumer-style proxy, q-ary BKW, sparse-row entropy and conservative quantum-stress columns.  These outputs are reproducible internal screens only; external expert cryptanalysis is still required before any security or deployment claim.

## Phase 8 strengthened attack-estimator framework

Version 0.10.0 adds internal working tools for LPN/ISD/BKW screening:

```bash
sable-he attack-estimator-info
sable-he attack-surfaces --candidate sable_cat1_depth1_review
sable-he attack-grid
sable-he attack-estimate --candidate sable_cat1_depth1_review
sable-he attack-package --output sable_phase8_attack_package
```

These tools are for manuscript strengthening and external-review preparation. They are not expert-certified attack estimates and they do not certify concrete SABLE-HE parameter sets.

## Phase 8 internal attack-estimator tooling

Version 0.10.0 adds a stronger internal LPN/ISD/BKW screening layer for
candidate parameter rows:

```bash
sable-he attack-estimator-info
sable-he attack-estimate --candidate sable_cat1_depth1_review
sable-he attack-package --output sable_phase8_attack_package
```

These commands are for paper strengthening and external cryptanalysis packages.
They do not certify SABLE-HE parameters.

## Phase 9 benchmark comparison framework

Version 0.10.0 adds an internal benchmark-comparison framework for top-venue evaluation work. It measures the SABLE-HE Python reference implementation on canonical low-depth workloads and writes external-baseline templates for OpenFHE, Microsoft SEAL, TFHE-rs, Concrete, and Lattigo.

Useful commands:

```bash
sable-he benchmark-info
sable-he benchmark-workloads
sable-he benchmark-sable --repetitions 3
sable-he benchmark-package --output phase9_benchmark_package
sable-he benchmark-baseline-template --output external_baseline_results_template.json
```

The framework does not invent external wall-clock values. External FHE libraries must be benchmarked independently on the same machine before manuscript comparison tables are finalized.

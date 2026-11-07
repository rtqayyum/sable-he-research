# SABLE-HE Research

[![PyPI](https://img.shields.io/pypi/v/sable-he-research.svg)](https://pypi.org/project/sable-he-research/)
[![Python](https://img.shields.io/pypi/pyversions/sable-he-research.svg)](https://pypi.org/project/sable-he-research/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SABLE-HE Research is a research implementation of **SABLE-HE**, a somewhat-homomorphic encryption scheme built only on LPN-type assumptions.
It follows the sparse-LPN architecture of Corrigan-Gibbs, Henzinger, Kalai and Vaikuntanathan (EUROCRYPT 2025, ePrint 2024/1760) and instantiates its linearly homomorphic layer with q-ary LPN.
The repository also contains sparse-LPN cryptanalysis tools, a key-additive secure-aggregation mode for federated learning, and an HPC experiment harness.

## Security status — read first

**The presets in `sable.PRESETS` are toy parameters and are insecure.**
Noise-free presets, presets with k ≤ 2, and presets with η·(n+1) ≲ 1 are broken by attacks shipped in `sable.sparse_attacks`.
Key generation with these presets emits `InsecureParametersWarning`.
The earlier "Category I/III/V" rows with k = 2 are also broken.
See [`docs/SECURITY_STATUS.md`](docs/SECURITY_STATUS.md) for the attacks, the new k = 5/6 review rows, and what remains open.
Nothing here is a certified cryptographic module.

## Install

```bash
python -m pip install sable-he-research            # reference implementation (pure Python)
python -m pip install "sable-he-research[fast]"    # + numpy/scipy kernels (fast_regev, fast_she)
```

From source:

```bash
git clone https://github.com/rtqayyum/sable-he-research.git
cd sable-he-research
python -m pip install -e ".[dev,fast]"
python -m pytest -q
```

## Key-additive secure aggregation (FL case study)

This is the configuration evaluated in the paper (results at commit `ac36e72`, key-sum attack at `7af1293`).
Replica counts come from the decoding-failure bound for the number of clients, and the summed key stays with a key authority.

```python
import numpy as np
from sable.fast_regev import FixedPoint, aggregate, decrypt_sum, encrypt, keygen, params_for_clients

K = 3
p = params_for_clients(n=65536, eta=0.003, clients=K)   # k=5, q=2^31-1, R from the bound (screened candidate, not certified)
fp = FixedPoint(p.q, scale=2**28, clip=3.9)             # 2^28 = scale_for_capacity(q//2, K) for K <= 1000
updates = [np.random.normal(0, 0.01, 7850) for _ in range(K)]
weights = [0.5, 0.3, 0.2]

keys = [keygen(p, seed=c) for c in range(K)]            # one secret per client
round_seed = 1234                                       # public; derives the sparse vectors
uploads = [encrypt(p, keys[c], fp.encode(updates[c], weights[c]), round_seed, noise_seed=100 + c) for c in range(K)]

B = aggregate(uploads, p.q)                             # aggregation server: sees uploads, never T

T = sum(keys) % p.q                                     # key authority only (committee or HSM)
avg = fp.decode(decrypt_sum(p, T, B, round_seed)["value"])   # key authority returns only the decoded sum
```

**Never give `T` to the party that sees individual uploads.**
With `T` and the uploads, the zero pattern of the summed LPN noise yields exact linear equations in every client key, and one round is enough to recover keys and individual updates (`sable.keysum_attack`, `tests/test_keysum_attack.py`).
The server and the key authority must not collude.

The presets in `sable.PRESETS` (for example `fl_demo_clean`, k = 1, η = 0) are insecure teaching examples for the readable reference implementation.
Do not use them for encrypted FL.

## Somewhat-homomorphic operations

`sable.sable` is the readable reference implementation.
`sable.fast_she` is the vectorized version used for benchmarks up to n = 262,144:

```python
from sable import fast_she as fs

p = fs.SheParams("demo", n=4096, k=5, q=fs.Q28, eta=0.0014, replicas=15)
keys = fs.keygen(p, seed=1)
A = fs.expand(keys, fs.encrypt(keys, 12, noise_seed=1))
B = fs.expand(keys, fs.encrypt(keys, 34, noise_seed=2))
value, votes = fs.decrypt(keys, fs.mul(A, B, p.q))   # 408
```

## Cryptanalysis tools

```python
from sable.sparse_attacks import sparse_layer_screen, solve_two_sparse_lpn, recover_s_known_plaintext
from sable.parameter_sets import screen_candidate
```

The candidate screen now combines the earlier clean-subset/ISD/BKW screens with sparse-specific screens: the known-plaintext expansion-key attack, low-sparsity propagation, and the m ≥ n^(k/2) sample threshold.

## Experiments on HPC

`evaluation/` holds the crypto track (attacks, correctness, benchmarks, parameter tables) and the FL track (MNIST and Fashion-MNIST with plaintext, SABLE, LWE-KAHE, SecAgg+, CKKS, BFV and Paillier).
[`docs/HPC_RUNBOOK.md`](docs/HPC_RUNBOOK.md) explains the two commands that run everything on Slurm from a pinned commit.

## CLI

```bash
sable-he --version
sable-he self-test
sable-he cryptanalysis-bundle --output review_bundle
sable-he candidate-parameters
```

## Main modules

- `sable.sable`, `sable.operations`: reference scheme and encrypted arithmetic.
- `sable.fast_regev`, `sable.fast_she`: vectorized kernels.
- `sable.sparse_attacks`: sparse-LPN screens and executable attacks.
- `sable.keysum_attack`: key-sum attack on key-additive aggregation when the server learns the summed key.
- `sable.parameter_sets`: candidate rows and the combined screen.
- `sable.fl`: FL utilities for the reference implementation (insecure toy presets only; use `sable.fast_regev` for encrypted FL).
- `sable.pqc`: backend-neutral PQC envelope format.

## Tooling history

Phases 4–10 added release engineering, review packages, proof-obligation ledgers, candidate-parameter templates, LPN/ISD/BKW estimators, benchmark templates and compaction theory.
Their documents live in `docs/phase*/`.
Where they make security claims, [`docs/SECURITY_STATUS.md`](docs/SECURITY_STATUS.md) takes precedence.

## Citation

Use [`CITATION.cff`](CITATION.cff).
Please also cite Corrigan-Gibbs, Henzinger, Kalai and Vaikuntanathan, "Somewhat Homomorphic Encryption from Linear Homomorphism and Sparse LPN", EUROCRYPT 2025.

## License

MIT License. See [`LICENSE`](LICENSE).

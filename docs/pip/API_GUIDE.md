# API Guide

The public package name is `sable`. The installable distribution name is `sable-he-research`.

## Core imports

```python
from sable import PRESETS, SableParams
from sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as ops
```

## Parameter presets

`PRESETS` is a dictionary of `SableParams` objects.

```python
from sable import PRESETS

print(sorted(PRESETS))
params = PRESETS["c7_standard_toy_clean"]
```

Important preset categories:

- `c7_standard_toy_clean`: default deterministic toy validation preset.
- `c7_standard_toy_noisy`: toy noisy validation preset.
- `toy_clean`, `toy_noisy`, `toy_depth2`: earlier validation presets.
- `prototype_medium`, `candidate_depth1_rough`, `c7_design_smallq`: estimator and experiment presets, not quick demos.

## Key generation

```python
kp = keygen_c7(params, seed=123)
```

`keygen_c7` creates the C7 relation-resistant coordinate compaction key. This is the conservative default in the package.

## Encryption and expansion

```python
compact_input = encrypt(kp, 3, seed=1)
expanded = expand(kp, compact_input)
```

The compact input ciphertext is used for small encrypted inputs. The expanded ciphertext is used for public homomorphic evaluation.

## Evaluation

```python
z1 = ops.add(x, y)
z2 = ops.mul(x, y)
z3 = ops.gate_xor(bit_x, bit_y)
z4 = ops.scalar_mul(x, 7)
```

## Compaction and decryption

```python
out = decrypt_c7(kp, compact_c7(kp, z2))
```

## Direct low-level APIs

The package also exposes earlier experimental compaction variants: C2, C3, C4, screened C7, estimators, and relation screens. They are preserved for reproducibility, but the recommended user-facing path is C7 coordinate compaction.

## Error handling

Most functions raise `ValueError` on incompatible parameters, replica mismatches, unsupported decomposition, or missing compaction keys.


## Federated-learning aggregation

See `docs/pip/FL_AGGREGATION.md` and `docs/fl/FEDERATED_LEARNING_GUIDE.md` for encrypted FedAvg, weighted aggregation, and tensor/model adapters.

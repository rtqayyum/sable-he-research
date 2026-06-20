# API Reference

## Core objects

```python
from sable.params import PRESETS, SableParams
from sable.sable import KeyPair
```

`SableParams` stores field modulus, dimensions, noise rates, replica count, and block-size metadata.

## Key generation

```python
from sable.sable import keygen_c7
kp = keygen_c7(PRESETS["c7_standard_toy_clean"], seed=123, mode="coordinate")
```

C7 coordinate mode is the conservative default after earlier C4 projective dictionaries were rejected by relation-surface screening.

## Encryption and expansion

```python
from sable.sable import encrypt, expand
ct_compact = encrypt(kp, 5, seed=1)
ct_expanded = expand(kp, ct_compact)
```

Input encryption is compact sparse-LPN/Regev-style. Evaluation uses expanded GSW-style matrices.

## Evaluation operations

```python
from sable import operations as A

z1 = A.add(x, y)
z2 = A.sub(x, y)
z3 = A.neg(x)
z4 = A.scalar_mul(x, 7)
z5 = A.mul(x, y)
z6 = A.square(x)
z7 = A.gate_xor(bit_x, bit_y)
```

Operations act on expanded ciphertext replicas.

## Compaction and decryption

```python
from sable.sable import compact_c7, decrypt_c7
out = decrypt_c7(kp, compact_c7(kp, z5))
```

C7 compaction homomorphically evaluates the final linear decryption row using a relation-resistant coordinate compaction layer.

## Estimator

```python
from sable.estimator import estimate
report = estimate(PRESETS["c7_standard_toy_clean"], depth=1, additions=1)
```

The report includes size estimates, correctness bounds, and heuristic screens. It is not a certified security proof.

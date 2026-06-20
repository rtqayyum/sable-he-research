# SABLE-HE API reference

This is a high-level reference for the public research API. The package import name is `sable`.

## Core modules

```python
from sable.params import PRESETS, SableParams
from sable.sable import keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations
```

## Parameter presets

```python
from sable.params import PRESETS

params = PRESETS["c7_standard_toy_clean"]
```

`SableParams` fields:

```text
name, q, n, k, eta, n_c, m_c, eta_c, replicas, c2_block_size
```

## Key generation

Recommended current path:

```python
kp = keygen_c7(params, seed=123, mode="coordinate")
```

Legacy and experimental paths are still available:

```python
keygen(params)
keygen_block_c2(params)
keygen_seeded_block_c2(params)
keygen_c4_basis(params)
keygen_screened_c7(params)
```

Use them only for reproducibility experiments unless you are actively studying those variants.

## Encryption and expansion

```python
ct_compact = encrypt(kp, message, seed=1)
ct_expanded = expand(kp, ct_compact)
```

The compact ciphertext is sparse Regev-style. The expanded ciphertext is a GSW-style matrix ciphertext suitable for public evaluation.

## Evaluation operations

```python
from sable.operations import add, sub, neg, scalar_mul, mul, square

ct_sum = add(ct_x, ct_y)
ct_diff = sub(ct_x, ct_y)
ct_neg = neg(ct_x)
ct_scaled = scalar_mul(ct_x, 5)
ct_product = mul(ct_x, ct_y)
ct_square = square(ct_x)
```

Public constants:

```python
from sable.operations import const_like, zero_like, one_like, add_plain, sub_plain

ct_zero = zero_like(ct_x)
ct_one = one_like(ct_x)
ct_seven = const_like(ct_x, 7)
ct_x_plus_2 = add_plain(ct_x, 2)
ct_x_minus_2 = sub_plain(ct_x, 2)
```

Boolean gates over bits embedded as `0/1` in `F_q`:

```python
from sable.operations import gate_and, gate_or, gate_xor, gate_not

ct_and = gate_and(ct_a, ct_b)
ct_or = gate_or(ct_a, ct_b)
ct_xor = gate_xor(ct_a, ct_b)
ct_not = gate_not(ct_a)
```

Higher-level arithmetic:

```python
from sable.operations import affine_combination, dot, poly_eval, product, balanced_product, quadratic_form
```

## Compaction and decryption

Recommended C7 path:

```python
ct_out = compact_c7(kp, ct_evaluated)
message = decrypt_c7(kp, ct_out)
```

Direct GSW last-row decryption is available for debugging:

```python
from sable.sable import direct_decrypt_gsw
print(direct_decrypt_gsw(kp, ct_evaluated))
```

## Estimator API

```python
from sable.estimator import estimate, format_estimate

report = estimate(params, depth=1, additions=1)
print(format_estimate(report))
```

## C7 relation-surface screen

```python
from sable.c7_relation_screen import estimate_c7_relations, format_c7_report

report = estimate_c7_relations(params, mode="standard")
print(format_c7_report(report))
```

## Version

```python
import sable
print(sable.__version__)
```

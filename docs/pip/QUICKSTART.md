# Quickstart

SABLE-HE encrypts field elements in a prime field `F_q`, expands compact ciphertexts into the evaluation representation, evaluates arithmetic publicly, compacts the result, and decrypts with the secret key.

All examples below use toy parameters. They are for correctness validation only.

## Encrypted multiplication

```python
from sable import PRESETS, keygen_c7, encrypt, expand, compact_c7, decrypt_c7
from sable import operations as ops

params = PRESETS["c7_standard_toy_clean"]
kp = keygen_c7(params, seed=123)

x = expand(kp, encrypt(kp, 3, seed=1))
y = expand(kp, encrypt(kp, 5, seed=2))

z = ops.mul(x, y)
out = decrypt_c7(kp, compact_c7(kp, z))

assert out == (3 * 5) % params.q
print(out)
```

## Encrypted addition and subtraction

```python
z_add = ops.add(x, y)
z_sub = ops.sub(x, y)

print(decrypt_c7(kp, compact_c7(kp, z_add)))  # (3 + 5) mod q
print(decrypt_c7(kp, compact_c7(kp, z_sub)))  # (3 - 5) mod q
```

## Public scalar multiplication

```python
z = ops.scalar_mul(x, 4)
out = decrypt_c7(kp, compact_c7(kp, z))
assert out == (4 * 3) % params.q
```

## Boolean gates over embedded bits

Bits are represented as `0` and `1` in `F_q`.

```python
a = expand(kp, encrypt(kp, 1, seed=10))
b = expand(kp, encrypt(kp, 0, seed=11))

xor_ct = ops.gate_xor(a, b)
and_ct = ops.gate_and(a, b)
or_ct = ops.gate_or(a, b)

print(decrypt_c7(kp, compact_c7(kp, xor_ct)))  # 1
print(decrypt_c7(kp, compact_c7(kp, and_ct)))  # 0
print(decrypt_c7(kp, compact_c7(kp, or_ct)))   # 1
```

## CLI quickstart

```bash
sable-he demo --operation mul --x 3 --y 5
sable-he demo --operation xor --x 1 --y 0
sable-he estimate --preset c7_standard_toy_clean --depth 1
```


## Federated-learning aggregation

See `docs/pip/FL_AGGREGATION.md` and `docs/fl/FEDERATED_LEARNING_GUIDE.md` for encrypted FedAvg, weighted aggregation, and tensor/model adapters.

# C3 seeded block-dictionary compaction

C3 is a storage refinement of the C2 block-dictionary compactor.

Dense C2 publishes one CLPN ciphertext for every nonzero block coefficient
vector.  Each CLPN ciphertext contains a dense public matrix `A` and a public
vector `b`.  Seeded C3 replaces every dense `A` with a public seed and keeps the
`b` vector explicit.

For a dictionary entry encrypting `x`, C3 stores

```text
(seed, b_0, ..., b_{m_c-1})
```

where each row of `A(seed)` is derived deterministically.  Decryption computes
`b - A(seed) r` by regenerating rows on demand.

Important distinction:

- Storage is reduced because dense `A` rows are not materialized.
- Security is not increased because an attacker can derive the same public `A`
  rows from the seeds.
- The public LPN sample count remains `dictionary_entries * m_c`.

This is therefore a memory/key-size engineering refinement plus a clearer attack
surface accounting step, not a cryptographic shortcut.

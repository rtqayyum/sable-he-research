# SABLE-HE-C3 seeded compaction and C2 public-sample surface report

This validation step adds two pieces to the SABLE-HE research package.

## 1. Seeded C3 block-dictionary compaction

C3 preserves the C2 block-dictionary semantics: for each block of the extended GSW secret and every nonzero coefficient tuple, the public key contains a CLPN encryption of the corresponding block inner product.  The change is representational: each dense CLPN public matrix `A` is generated from a public seed, so the key stores only the `b` vector plus seed metadata.

This reduces materialized storage and memory traffic.  It does **not** reduce the number of LPN samples exposed to an adversary, because every `A` row remains public and efficiently derivable from the seed.

The executable components are:

```text
src/sable/clpn_seeded.py
src/sable/clpn_c3_seeded.py
src/sable/estimator_seeded.py
experiments/run_seeded_c2.py
experiments/run_seeded_estimator.py
```

The toy clean seeded-C3 correctness check succeeds for multiplication and `xy+z`; see `docs/c3_seeded_correctness_output.txt`.

## 2. Dedicated C2/C3 public-sample attack surface

The C2 dictionary creates more than a simple `entries * m_c` collection of CLPN rows.  The new screen explicitly counts:

1. sparse-LPN expansion-key rows;
2. within-entry CLPN row differences, where subtracting two rows of the same dictionary ciphertext cancels the encrypted dictionary message;
3. cross-entry dictionary differences within the same block, where differences between entries create LPN-like samples involving the joint secret `(r, s_block)`;
4. sparse-row collision entropy;
5. seeded-storage reduction, marked as informational only.

The executable components are:

```text
src/sable/c2_attack_surface.py
experiments/run_c2_attack_surface.py
tests/test_c2_attack_surface.py
```

Generated outputs:

```text
docs/c2_attack_surface_toy_noisy.txt
docs/c2_attack_surface_design_smallq.txt
```

## Main conclusion

Seeded C3 is useful for storage, but the dominant research bottleneck is now public-sample security of the C2 dictionary.  The current toy and design presets remain research-only.  The next design step should be a C4 compactor that avoids publishing a full closed block dictionary, for example by using sparse/limited dictionaries, randomized block challenges, CRT lanes with restricted tuple sets, or a different code-based LHE layer with fewer plaintext-cancelling relations.

## Validation

The current repository test suite reports:

```text
52 passed
```

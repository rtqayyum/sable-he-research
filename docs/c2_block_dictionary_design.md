# SABLE-HE-C2 block-dictionary compactor

Status: research-validation candidate, not production cryptography.

## Motivation

The v1 CLPN compactor publishes one q-ary LPN/CLPN encryption of every coordinate of the extended GSW secret `tilde{s}`.  To compact a final GSW row `r`, the evaluator computes a linear homomorphic sum

```text
sum_i r_i Enc(tilde{s}_i).
```

If the row has `B` nonzero coordinates, this adds `B` independent CLPN noise vectors.  For q-ary symmetric noise, the aggregate nonzero probability after `B` independent terms is

```text
eta_B = (q-1)/q * (1 - (1 - q*eta_c/(q-1))^B).
```

Thus correctness tends to force `eta_c = O(1/B)`, which creates a low-noise LPN security bottleneck.

## C2 idea

Partition the `N = n+1` coordinates of `tilde{s}` into blocks of length `ell`.  For each block `j` and every nonzero coefficient vector `u in F_q^{ell_j}`, publish

```text
CLPN.Enc_r(<u, tilde{s}_j>).
```

To compact a final row `r`, split it into block tuples `r_j`.  For every nonzero block tuple, add exactly one precomputed ciphertext:

```text
Compact_C2(r) = sum_{j : r_j != 0} CLPN.Enc_r(<r_j, tilde{s}_j>).
```

The plaintext is still

```text
sum_j <r_j, tilde{s}_j> = r · tilde{s},
```

but the number of accumulated CLPN noise terms is now

```text
t_C2(r) = #{j : r_j != 0} <= min(supp(r), ceil(N/ell)).
```

For dense rows this can improve the compaction-noise term by about a factor of `ell`.  For sparse rows it may not help.

## Cost

The public dictionary contains

```text
sum_j (q^{ell_j} - 1)
```

CLPN ciphertexts.  This is only plausible for small `q` and small `ell`; it is not feasible for large prime fields with `ell >= 2`.

C2 therefore makes most sense for:

- small-field Boolean/arithmetic workloads, e.g. `q = 3, 5, 7`;
- CRT-laned designs where each lane uses a small prime field;
- dense final rows where reducing `B` to `ceil(N/ell)` is meaningful;
- research validation of the compaction bottleneck.

## Security interpretation

C2 does not remove the need for LPN security analysis.  It increases the public CLPN sample surface from roughly `N * m_c` rows to roughly

```text
m_c * sum_j (q^{ell_j} - 1)
```

rows.  Under semantic security of CLPN, encrypted block inner products hide their messages, but the increased number of public noisy-linear samples must be included in any attack-cost screen.  The estimator therefore reports both the improved correctness/noise term and the larger attack surface.

## Validation snapshot

The executable prototype now includes:

- `sable.clpn_c2.build_dictionary`;
- `sable.clpn_c2.eval_lin` for block dictionaries;
- `sable.sable.keygen_block_c2`;
- `sable.sable.compact_block_c2`;
- `sable.estimator_c2.summarize_params_c2`.

Current tests:

```text
39 passed
```

The clean toy block-dictionary test reports:

```text
preset=c2_toy_clean q=7 N=13 block_size=2
dictionary_entries=294
case=mul got=3 expected=3 pass=True
case=xy_plus_z got=4 expected=4 pass=True
```

## Current conclusion

C2 is useful as a research refinement because it exposes the real tradeoff:

```text
less compaction noise  <-->  larger public CLPN dictionary/sample surface.
```

It does not yet produce certified secure parameters.  The next required step is a sparse/q-ary LPN estimator that treats the larger C2 public sample surface, sparse-row structure, and low-noise regimes more accurately.

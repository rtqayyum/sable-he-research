# SABLE-HE-C2 validation report

## Implemented in this revision

This revision adds a block-dictionary C2 compactor in addition to the previous q-ary plurality C2 compatibility layer.

New or updated components:

- `src/sable/clpn_c2.py` - block dictionary construction and linear evaluation, plus compatibility wrappers.
- `src/sable/codes.py` - q-ary weighted repetition helpers and q-ary plurality bound.
- `src/sable/crt.py` - CRT helper for small-lane experiments.
- `src/sable/sable_crt.py` - experimental CRT lane wrapper.
- `src/sable/sable.py` - `keygen_block_c2`, `compact_block_c2`, `decrypt_block_c2`.
- `src/sable/estimator_c2.py` - C2 dictionary size, noise, and sample-surface estimator.
- `experiments/run_c2_block_dictionary.py` - clean end-to-end block-dictionary validation.

## Test result

```text
39 passed
```

See `docs/test_output_c2.txt`.

## Clean block-dictionary correctness result

```text
preset=c2_toy_clean q=7 N=13 block_size=2
dictionary_entries=294
case=mul got=3 expected=3 pass=True
case=xy_plus_z got=4 expected=4 pass=True
```

See `docs/c2_block_dictionary_correctness.txt`.

## Estimator result: c2_toy_noisy

For `q=7`, `N=17`, `ell=2`, depth 1:

- v1 coordinate compaction terms: 16;
- C2 worst-case block compaction terms: 9;
- v1 aggregate compaction noise: about `0.0079651`;
- C2 aggregate compaction noise: about `0.00448951`;
- C2 dictionary entries: 390.

This confirms that C2 reduces compaction-noise accumulation on the toy setting, but increases public key size.

## Estimator result: c2_design_smallq

For `q=7`, `N=513`, `ell=3`:

- depth 1 row support is still sparse enough that C2 gives no term reduction in the worst-case bound: v1 terms 81, C2 terms 81;
- depth 2 row support saturates the coordinate space, so C2 reduces terms from 513 to 171;
- dictionary size is 58,482 CLPN ciphertexts;
- dense toy field-entry estimate is roughly 122.9 billion field entries, so practical implementations need seeded generation, compression, or a different compactor representation.

## Current research conclusion

The C2 block dictionary is mathematically coherent and executable for small toy parameters.  It is not yet a practical security-grade parameter set.  Its value is that it turns the previous compaction bottleneck into a measurable tradeoff: fewer accumulated noise terms versus a larger CLPN sample surface.

## Next recommended step

Build a dedicated sparse/q-ary-LPN estimator for C2 that models:

1. public sample multiplication caused by block dictionaries;
2. low-noise clean-subset attacks;
3. sparse-row structural attacks;
4. q-ary BKW variants;
5. Prange/ISD-style decoding in the relevant q-ary regimes;
6. CRT-laned small-field variants.

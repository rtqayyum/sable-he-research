# SABLE-HE-C4 validation report

## Implemented

- `src/sable/additive_basis.py`: projective representatives, random basis generation, sparse decomposition, sample coverage, and low-weight relation screens.
- `src/sable/clpn_c4_basis.py`: C4 key generation, compaction, decryption helpers, term counting, and key-size estimation.
- `src/sable/c4_estimator.py`: v1/C2/C3/C4 public-surface comparison.
- `experiments/run_c4_coverage.py`: coverage and relation screen output.
- `experiments/run_c4_compaction_correctness.py`: end-to-end correctness check.
- `experiments/run_c4_v123_comparison.py`: public surface comparison.
- `paper/sable_he_latex/appendices/h_c4_projective_basis.tex`: mathematical appendix.

## Validation result

The pytest suite passes with the C4 additions. See `docs/test_output_c4_projective.txt`.

## Main finding

C4 projective compaction improves over C2/C3 full dictionaries by replacing
`q^b - 1` public entries per block with `(q^b - 1)/(q - 1)` entries. It keeps
one CLPN compaction term per active block. This is better than C3 seeding,
because seeding reduced storage but not the public sample surface; C4 reduces
both storage and public rows.

## Remaining risk

C4 is still structured. The projective dictionary exposes one encrypted inner
product per projective line. The next required research step is a dedicated
large-sample q-ary/sparse-LPN attack estimator for the projective public key.

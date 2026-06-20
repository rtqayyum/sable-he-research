# SABLE-HE validation v0.4 - C3 seeded block-dictionary compaction

This release builds on the C2 block-dictionary compactor and adds a seeded
CLPN storage model.  The evaluator still receives the same public LPN sample
surface, but the random CLPN matrices are derived from public seeds rather than
stored densely.  The public `b` vectors remain explicit.

Main additions:

- `sable.clpn_seeded`: seeded linearly homomorphic q-ary LPN ciphertexts.
- `sable.clpn_c3_seeded`: seeded block-dictionary C2/C3 compaction keys.
- `sable.qary_lpn_estimator`: dedicated sparse/q-ary-LPN public-sample screen.
- `sable.estimator_seeded`: size, correctness, and attack-surface estimator
  for the seeded C3 compactor.
- End-to-end tests for seeded compaction.
- Paper Appendix F describing the C3 seeded storage model.

Security status: research validation only.  Seeded storage reduces materialized
key size but does not reduce the number of public LPN samples available to an
attacker.

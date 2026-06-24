# Parameter-selection methodology

The bundled parameter framework follows this workflow:

1. Fix the target workload: additive-only FL, degree-2 arithmetic, or another bounded-depth circuit family.
2. Fix the multiplicative depth and addition budget.
3. Choose field modulus `q`, sparse dimension `n`, sparse row weight `k`, and sparse-LPN noise `eta`.
4. Estimate row support and evaluation error.
5. Choose compaction dimension, code length, and compaction noise.
6. Run the first-pass screens: clean subset, Prange/ISD, BKW proxy, sparse-row entropy, and compaction row-difference surfaces.
7. Mark the set as `candidate-for-external-review`, not certified.

These screens intentionally err on the side of rejecting weak settings.  Passing them is necessary but not sufficient for a security claim.

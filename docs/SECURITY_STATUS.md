# Security status (v0.12.0)

This page records what is known to be broken, what was changed, and what is
still open.  It supersedes any security wording in the Phase 5–10 documents.

## Relation to prior work

SABLE-HE follows the architecture of Corrigan-Gibbs, Henzinger, Kalai and
Vaikuntanathan, *Somewhat Homomorphic Encryption from Linear Homomorphism and
Sparse LPN* (EUROCRYPT 2025, IACR ePrint 2024/1760): sparse-LPN matrix
ciphertexts, matrix addition and multiplication, and a compaction step that
uses linearly homomorphic encryptions of the secret.  SABLE-HE instantiates the
linearly homomorphic layer with q-ary LPN (repetition code plus plurality
decoding) so that every component rests on LPN-type assumptions rather than
DDH/DCR/QR.  Its contribution is that instantiation, concrete parameters, an
implementation, and the cryptanalysis below.

## What is broken

| Item | Attack | Status |
|---|---|---|
| Noise-free presets (`fl_demo_clean`, `toy_clean`, all `*_clean`) | The expansion-key matrix X_n encrypts the known value 1, so (X_n − I)·(−s, 1) = 0 is a linear system in s. One Gaussian elimination recovers s, and then every expanded ciphertext decrypts. | Insecure toy presets. Key generation now emits `InsecureParametersWarning`. |
| Presets with η·(n+1) ≲ 1 (`prototype_medium`, `c7_design_smallq`, `c2_candidate_depth1`, `candidate_depth1_rough`, …) | Same attack. It succeeds with probability (1−η)^(n+1) per attempt. | Insecure. |
| Candidate rows with k = 2 (`sable_cat{1,3,5}_depth1_review`) and k = 1 (`sable_cat1_depth2_stress`) | Sparse LPN with k ≤ 2 is a noisy two-variable linear system. Breadth-first propagation plus plurality voting recovers the secret in near-linear time (`sable.sparse_attacks.solve_two_sparse_lpn`): n = 65,536, η = 0.003 and 20n samples take about 15 s in pure Python. The expansion key publishes (n+1)² samples, so the hybrid that replaces the expansion key under sparse LPN is unsupported at k ≤ 2. | Rejected. Kept in the table only as a record. |

The earlier estimators reported 160–209 bits for the k = 2 rows because they
applied dense-LPN ISD/BKW formulas to a sparse surface.  The candidate screen
now also runs the sparse-specific screens in `sable.sparse_attacks`.

## What changed

* `sable.sparse_attacks`: known-plaintext expansion-key screen, low-sparsity
  propagation screen, the m ≥ n^(k/2) sample-threshold screen, a q-ary
  plurality correctness bound, and executable attacks.
* New review rows `sable_k5_cat1_depth1`, `sable_k6_cat1_depth1`,
  `sable_k5_cat3_depth1` and `sable_k6_cat5_depth1`.  They pass every
  internal screen, but the k = 5 rows carry a thin sample margin
  (k/2 − log_n m ≈ 0.5).  They are review targets, not certified parameters.
* `sable.fast_regev`: key-additive aggregation (per-client keys, server sees
  only the summed key), seeded public vectors, so uploads are R·⌈log₂q⌉ bits
  per coordinate.
* `sable.fast_she`: vectorized SHE pipeline with lazily derived, seeded keys.

## Still open

* No external cryptanalysis.  Constant-k sparse LPN with ≈ n² samples is a
  strong assumption; k = 6 rows have a wider margin than k = 5.
* The security proof in `docs/phase6` is an outline.  The paper needs a full
  hybrid argument with exact sample counts and the compaction lemma.
* The FL case study uses one client key per run.  It assumes the summed key
  reaches the server through a key-aggregation step (committee or secret
  sharing) that is not implemented here.

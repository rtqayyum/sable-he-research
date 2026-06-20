# Validation plan

The next research phase has four validation tracks.

## Track A: formal proof audit

- Verify the sparse-LPN input encryption reduction.
- Verify the GSW-style expansion-key hybrid under multi-message sparse-LPN samples.
- Verify that the code/LPN compaction key does not introduce circular security because the secrets `t`, `s`, and `r` are independent.
- Prove the addition and multiplication invariants for `(w, epsilon)`-good ciphertexts.
- Prove the final replica/plurality correctness bound.

## Track B: correctness and parameter estimation

The estimator computes:

- fresh expanded row support `w0 = (k+1)^2`;
- fresh expanded error probability `eps0 = (k+2) eta`;
- recursive multiplication quality `eps <- eps_left + w_left eps_right`;
- q-ary compaction noise using the q-ary piling-up formula;
- conservative repetition/plurality failure bounds;
- ciphertext and key-size estimates.

## Track C: toy implementation and Monte Carlo testing

The prototype tests:

- Regev-style input encryption;
- GSW-style matrix encryption;
- expansion from compact input ciphertexts;
- homomorphic addition and multiplication;
- code/LPN compaction;
- end-to-end evaluation of low-degree circuits.

## Track D: cryptanalysis and baselines

Before publication, compare against:

- TFHE/FHEW for Boolean circuits;
- BFV/BGV for exact arithmetic over small rings/fields;
- LPN secure aggregation for additive workloads.

Also evaluate attacks including BKW, information-set decoding, low-noise LPN attacks, and large-sample attacks from evaluation keys.

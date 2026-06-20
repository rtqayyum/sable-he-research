# Cryptanalysis checklist for SABLE-HE

This checklist is intentionally conservative. Passing the toy tests is not evidence of cryptographic security.

## Sparse-LPN side

- Estimate concrete cost of BKW-style attacks for the chosen `(q, n, k, eta)`.
- Estimate information-set decoding / Prange-style attacks against the corresponding noisy sparse-code view.
- Analyze low-noise regimes: very small `eta` improves correctness but can weaken LPN-style hardness.
- Account for the large number of public samples introduced by expansion keys.
- Check whether row sparsity introduces distinguishers beyond standard sparse-LPN assumptions.
- Analyze whether using the same GSW secret across many matrix encryptions creates exploitable structure.

## Code/LPN compaction side

- Estimate LPN hardness for `(q, n_c, m_c, eta_c)` under many public compaction-key ciphertexts.
- Check the aggregate q-ary noise after linear combinations of up to `B` encrypted secret-key coordinates.
- Replace repetition decoding with a serious q-ary code for any claimed parameter set.
- Verify that the compaction key encrypts `tilde{s}` under an independent secret `r`, avoiding direct circular security.

## Evaluation-key leakage

- Expansion key publishes GSW encryptions of `tilde{t}_i` under secret `s`.
- Compaction key publishes CLPN encryptions of `tilde{s}_i` under secret `r`.
- The security proof must use a multi-hybrid argument replacing these encryptions before replacing challenge ciphertexts.

## Correctness

- Track row support and error probability after every gate.
- Orient matrix multiplication so the lower-sparsity input is on the left where possible.
- Validate depth-1 and depth-2 circuits before attempting larger workloads.
- Report decryption-failure probability, not only average success.

## Claims to avoid

- Do not claim full FHE.
- Do not claim production security.
- Do not claim superiority over lattice FHE without benchmarks.
- Do not rely on "NP-hard decoding" as a concrete average-case security argument.

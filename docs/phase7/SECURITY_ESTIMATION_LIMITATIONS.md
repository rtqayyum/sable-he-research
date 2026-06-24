# Security-estimation limitations

The Phase 7 screens are rejection diagnostics.  They are not complete LPN estimators.

The current package reports:

- sparse-LPN expansion-key sample counts;
- q-ary LPN compaction-key sample counts;
- same-entry compaction row-difference samples;
- input-ciphertext sample growth under FL deployment assumptions;
- clean-subset style finite screens;
- conservative correctness/noise budgets.

Missing before a secure-parameter claim:

- specialized sparse-q-ary-LPN BKW estimates;
- information-set decoding estimates for the selected q-ary code family;
- quantum cost models;
- memory-time tradeoff analysis;
- external review of low-noise and large-sample surfaces;
- implementation-side leakage review.

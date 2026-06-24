# Parameter Review Limitations

Phase 7 does **not** certify security.  It is a structured starting point for review.  In particular:

1. The clean-subset and secret-search screens are first-pass lower-bound-style diagnostics, not complete attack models.
2. BKW-style attacks, ISD variants, sparse-LPN distinguishers, and large-sample q-ary-LPN attacks require specialist review.
3. The compaction layer still needs a final paper-grade q-ary error-correcting code and decoding-failure analysis.
4. The depth-2 templates are estimator stress tests and are not intended as practical recommendations.
5. The tables do not account for all side channels, implementation faults, entropy failures, or adaptive misuse.

Use the generated parameter package as a disclosure artifact for cryptographers, not as a production configuration.

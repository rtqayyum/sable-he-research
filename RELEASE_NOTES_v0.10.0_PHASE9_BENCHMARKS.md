# SABLE-HE v0.10.0 — Phase 9 benchmark comparison framework

This internal strengthening release adds reproducible benchmark tooling for manuscript evaluation.

Added:

- `sable.benchmarking` module;
- benchmark workload registry;
- measured SABLE Python reference timing suite;
- external FHE baseline specifications for OpenFHE, Microsoft SEAL, TFHE-rs, Concrete, and Lattigo;
- external result JSON template;
- benchmark package generator;
- CLI commands `benchmark-info`, `benchmark-workloads`, `benchmark-sable`, `benchmark-package`, `benchmark-baseline-template`, `benchmark-protocol`, and `benchmark-compare`.

Scope:

- measures SABLE locally;
- prepares reproducible external-baseline collection;
- does not fabricate external benchmark numbers;
- does not certify SABLE parameter sets.

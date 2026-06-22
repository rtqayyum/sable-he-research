# Future hardened core backend plan

The current package is a Python research implementation. A hardened core should separate public APIs from cryptographic kernels.

Suggested future layout:

```text
sable-core-rs/       # Rust implementation of finite-field, sparse, encoding, and evaluation kernels
sable-python/        # Python bindings and public API compatibility layer
sable-kats/          # deterministic vectors shared across implementations
sable-fuzz/          # fuzzing harnesses
sable-bench/         # reproducible benchmarks
```

Key hardening requirements:

- reviewed randomness interfaces;
- constant-time handling where secrets are involved;
- decoder-failure handling that does not leak through repeated oracle behavior;
- no private/generated artifacts in the public release branch;
- stable serialization and versioned schemas;
- independent cryptanalysis before any production security claim.

# C8 production-hardening requirements

## Implementation hardening

- Replace pure-Python prototype arithmetic with memory-safe Rust or constant-time
  C/C++ plus bindings.
- Remove secret-dependent branches and memory accesses where they affect secrets.
- Use constant-time finite-field arithmetic for secret-dependent data.
- Add explicit zeroization for secrets.
- Add deterministic serialization formats for public keys, secret keys,
  ciphertexts, evaluation keys, parameter sets, and test vectors.
- Add domain-separated randomness and seed expansion.
- Add strict parameter validation and reject unknown parameter sets.
- Add API-level circuit-depth accounting and refuse unsupported depth.
- Add ciphertext/key versioning.

## Testing and verification

- Unit tests for every finite-field and sparse-matrix operation.
- Property tests for homomorphic correctness.
- KAT vectors for all frozen parameter profiles.
- Fuzzing for deserialization and API misuse.
- Differential tests against a mathematical reference implementation.
- Static analysis and dependency audits.
- Reproducible builds.

## Cryptographic hardening

- Formal IND-CPA proof in game-hopping style.
- Large-sample q-ary-LPN estimator.
- Sparse-LPN estimator with BKW, ISD/Prange, and low-noise screens.
- Public evaluation-key leakage analysis.
- Compaction-key relation analysis.
- Decryption-failure analysis and safe failure handling.
- Multi-user and multi-ciphertext security analysis.
- Parameter profiles with security margins.

## Deployment hardening

- No production use of toy presets.
- Separate experimental and security-grade parameter namespaces.
- Explicit key lifecycle policy.
- Guidance for authenticated transport and signature wrapping using approved PQC.
- Clear statement that SABLE provides privacy of computation only; it does not
  prove server correctness unless combined with a verification layer.

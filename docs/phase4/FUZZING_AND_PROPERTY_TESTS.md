# Fuzzing and property-test plan

Phase 4 keeps the public package pure Python, but prepares a fuzzing plan for the future hardened core.

Recommended properties:

- Finite-field operations are closed modulo `q`.
- `Decrypt(Compact(EvalAdd(Expand(Enc(x)), Expand(Enc(y))))) = x + y mod q` for zero-noise presets.
- `Decrypt(Compact(EvalMul(...))) = x*y mod q` for supported low-depth zero-noise presets.
- Fixed-point encoding/decoding round-trips within the configured scale.
- PQC envelope verification rejects tampered schema, ciphertext, signature, sender key, and metadata-binding changes.
- Cryptanalysis bundles are deterministic for a fixed release.
- Public repo hygiene never allows `paper/`, PDFs, or generated logs into release branches.

For the Python package, these checks are implemented as deterministic pytest tests and CLI smoke tests. A future Rust/C/C++ core should add libFuzzer/AFL/honggfuzz harnesses for parsing, serialization, sparse rows, decoders, and envelope verification.

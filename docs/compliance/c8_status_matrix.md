# C8 status matrix: what is ready and what is not

This matrix separates three different meanings of "ready".

| Target | Current status | Why |
|---|---|---|
| Research artifact | Ready | The manuscript, prototype, arithmetic tests, negative-result trail, and relation-screening tools are present. |
| Internal validation prototype | Ready | Toy correctness, operation coverage, and estimator tests are automated. |
| Independent cryptanalysis package | Ready to submit | The package contains a construction, threat model, tests, known limitations, and attack-surface diagnostics. |
| Production cryptography | Not ready | Production crypto requires independent cryptanalysis, hardened implementation, misuse-resistant APIs, side-channel review, fuzzing, KATs, reproducible builds, and deployment guidance. |
| Certified secure parameter set | Not ready | No authority or independent evaluator has validated SABLE parameter security. Current presets are toy/research presets. |
| FIPS/CAVP validation | Not eligible as SABLE | CAVP validates approved or NIST-recommended algorithms and components. SABLE is not an approved NIST algorithm. |
| FIPS 140-3 module validation | Not ready | Module validation requires an implementation using approved algorithms/components and a laboratory validation process. |
| Standardization-ready submission candidate | Partially ready | The specification, tests, vectors, and comparison framework exist, but independent cryptanalysis and stable security parameters are still missing. |

Conclusion: C8 should be described as **audit-ready and pre-standardization-candidate-ready**, not as production-certified cryptography.

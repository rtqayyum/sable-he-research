# Security Status

SABLE-HE Research is **not production cryptography**.

Current status:

| Gate | Status | Meaning |
|---|---|---|
| Research artifact | green | Construction, prototype, tests, and manuscript are present. |
| Internal validation | green | Toy correctness, arithmetic tests, and relation screens are automated. |
| Audit package | green | Suitable for independent cryptanalysis with limitations disclosed. |
| Production cryptography | red | Requires independent cryptanalysis, hardened implementation, side-channel review, audit, and stable parameters. |
| Certified parameters | red | Requires externally reviewed parameter security and attack-cost estimates. |
| Standardization readiness | amber | Draft materials exist, but parameters and external analysis are not frozen. |

## Why this warning is strict

New cryptographic schemes cannot be self-certified by their designers. A production deployment would require, at minimum:

1. independent cryptanalysis;
2. stable parameter generation and attack-cost estimates;
3. side-channel-resistant implementation;
4. fuzzing and memory-safety review;
5. external audit;
6. reproducible known-answer tests;
7. comparison against established HE libraries on identical workloads.

The package deliberately keeps these limitations visible.

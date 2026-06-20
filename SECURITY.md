# Security Policy

## Status

SABLE-HE is a research prototype and candidate cryptographic construction. It is
not approved for protecting production data, regulated workloads, or safety-
critical systems.

## Reporting security issues

Report suspected vulnerabilities, attacks, incorrect proofs, parameter failures,
side-channel issues, or implementation bugs by opening a private advisory in the
project repository or contacting the maintainers through the configured security
contact.

Please include:

- affected version or commit;
- threat model;
- parameter set;
- reproduction steps or attack outline;
- expected and observed behavior;
- whether the issue affects algebraic correctness, IND-CPA security,
  side-channel leakage, parameter estimates, or API misuse resistance.

## Supported versions

Only the latest research branch should be analyzed. Earlier C2/C3/C4 variants
remain in the repository for reproducibility and negative-result documentation;
C7 coordinate relation-resistant compaction is the current main candidate.

## Safe-use notice

Do not use this prototype to protect real data. The code is written for
validation, testing, and cryptanalysis. A production implementation must be
constant-time where relevant, memory-safe, fuzzed, reviewed, benchmarked against
external libraries, and audited independently.

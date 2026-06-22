# Security Policy

## Status

SABLE-HE Research is a public research implementation of a post-quantum code/LPN-based leveled homomorphic-encryption construction. It is intended for research, validation, cryptanalysis, and reproducible encrypted-aggregation experiments.

It is **not** a certified cryptographic module, does **not** provide certified parameter sets, and should not be used as the sole mechanism for protecting production, regulated, safety-critical, or high-value data.

## Supported versions

Only the latest tagged public release receives documentation and bug-fix attention. Older experimental branches and historical design variants may remain in the repository for reproducibility, but the main public API is the current SABLE-HE relation-resistant coordinate-compaction API and the `sable.fl` federated-learning aggregation API.

| Version | Supported |
| --- | --- |
| Latest public release | Yes |
| Older research snapshots | Best-effort only |
| Historical experimental variants | Reproducibility only |

## What to report

Please report:

- algebraic correctness failures;
- attacks on the sparse q-ary LPN or q-ary code/LPN surfaces;
- parameter-estimation mistakes;
- vulnerabilities in encrypted aggregation workflows;
- serialization, randomness, or reproducibility bugs;
- side-channel or timing concerns;
- misleading documentation or unsafe API behavior.

## How to report

Prefer GitHub's private vulnerability reporting or a private security advisory if enabled in the repository. If private reporting is not enabled, open a minimal public issue that says a private security report is needed, without publishing exploit details.

A good report includes:

- affected version or commit;
- operating system and Python version;
- parameter set and command used;
- threat model;
- reproduction steps or attack outline;
- whether the issue affects correctness, privacy, parameter estimates, side-channel leakage, or API misuse resistance.

## Disclosure policy

The maintainers will acknowledge valid reports, reproduce them when possible, and coordinate disclosure timelines for security-sensitive findings. Because this is a research project, cryptanalytic reports are welcome even when they show limitations rather than software bugs.

## Safe-use notice

Do not treat this package as production-certified post-quantum cryptography. Production systems should use standardized and validated cryptographic primitives for transport security, authentication, package signing, and key management, and should treat SABLE-HE Research as an experimental HE component until it has independent cryptanalysis, hardened implementation review, and certified parameter sets.

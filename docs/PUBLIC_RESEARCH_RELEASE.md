# Phase 1: Public Research Release

This repository is prepared as a public research release for SABLE-HE Research.

## Positioning

SABLE-HE Research is a post-quantum code/LPN-based homomorphic-encryption research implementation. The package is intended for reproducible experiments, federated-learning aggregation demos, cryptanalysis, parameter-estimation work, and independent review.

The project should not be advertised as certified production cryptography. The correct claim is:

> SABLE-HE Research is a public research implementation of a candidate post-quantum code/LPN-based leveled homomorphic-encryption scheme for low-degree encrypted arithmetic and federated aggregation.

## What is included

- Python package and CLI.
- Encrypted additive aggregation and FedAvg helpers.
- Plain/decryptor-side robust aggregation helpers.
- Tensor adapters for Python, NumPy, TensorFlow/Keras, and PyTorch objects when optional dependencies are installed.
- Tests and examples.
- Public security status and reporting policy.
- Cryptanalysis challenge and issue templates.
- PyPI and GitHub release workflow support.

## Public release checklist

1. Confirm tests pass.
2. Confirm README install command works.
3. Confirm `SECURITY.md` is visible on GitHub.
4. Confirm PyPI page renders README correctly.
5. Create a GitHub release from the version tag.
6. Attach wheel, source distribution, paper PDF, and release notes if desired.
7. Open a pinned GitHub discussion or issue inviting cryptanalysis.
8. Announce using the safe claim language in this document.

## Recommended announcement wording

SABLE-HE Research v0.2.1 is a public research release of a post-quantum code/LPN-based leveled homomorphic-encryption toolkit for encrypted federated aggregation experiments. It includes a Python package, CLI, encrypted FedAvg APIs, tensor adapters, documentation, and a cryptanalysis challenge. The release is intended for research and independent review, not for certified production deployment.

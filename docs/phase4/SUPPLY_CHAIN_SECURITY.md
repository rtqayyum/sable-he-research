# Supply-chain security notes

Phase 4 adds public-package hygiene and reproducibility checks. For stronger supply-chain posture, maintainers should also consider:

- PyPI Trusted Publishing from GitHub Actions.
- Immutable version tags and GitHub releases.
- Signed commits/tags where possible.
- GitHub branch protection for release branches.
- GitHub Actions CI for tests, build, Twine check, and CLI smoke tests.
- OpenSSF Scorecard workflow for repository security-health signals.
- Artifact attestations or Sigstore/Cosign for future binary artifacts.

These are release-integrity controls. They do not certify the cryptographic construction or parameter security.

# Phase 4 build and test report

This release adds hardened-reference preparation material:

- `sable.hardening` and `sable.phase4` public release-engineering helpers;
- deterministic KAT generation and verification;
- public repository hygiene checks;
- release artifact checks;
- Phase 4 CLI commands;
- deterministic vectors under `vectors/phase4/`;
- GitHub Scorecard workflow template;
- release-engineering documentation.

Validation performed during package assembly:

```text
pytest collected: 125 tests
pytest status: pass
repo hygiene: pass
release check: pass
KAT verification: pass
```

The package remains a public research implementation and is not certified production cryptography.

# Release notes: v1.0-C8 readiness package

C8 does not claim production or certification status. It packages SABLE-HE-C7
for the next professional review stage: independent cryptanalysis,
implementation hardening, parameter validation, and standardization preparation.

Added:

- `SECURITY.md` vulnerability-reporting and safe-use notice.
- C8 production/certification/standardization status matrix.
- C8 certification strategy.
- C8 production-hardening requirements.
- C8 standardization-submission checklist.
- C8 readiness-gate tool.
- Toy deterministic KAT-vector generator and generated vector.
- CI workflow template.

Validation target:

- research artifact: green;
- internal validation: green;
- audit package: green;
- production cryptography: red;
- certified parameters: red;
- standardization-ready: amber.

This strict status is intentional. It prevents unsupported security claims while
making the project ready for the next evidence-gathering phase.

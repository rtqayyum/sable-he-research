# C8 certification and validation strategy

## A. What can be done internally

The project team can prepare:

- a stable specification;
- reference implementation;
- deterministic known-answer tests;
- formal proof document;
- implementation security policy;
- parameter-estimation workbench;
- side-channel checklist;
- fuzzing harness;
- API misuse tests;
- benchmark protocol;
- cryptanalysis challenge instances.

## B. What requires external parties

The following cannot be granted internally:

- NIST/FIPS approval of a new algorithm;
- CAVP validation of a non-approved algorithm;
- CMVP/FIPS 140-3 module validation;
- independent cryptanalysis;
- third-party audit opinion;
- standardization acceptance.

## C. Practical certification path

1. Keep SABLE as a research candidate while using approved PQC algorithms for
   authentication/key establishment in any surrounding protocol.
2. Prepare a public cryptanalysis challenge and parameter-estimation notebook.
3. Submit the paper and reference implementation for peer review.
4. Obtain independent implementation audit after the algorithm is stable.
5. If the community accepts the construction, pursue an HE community-standard
   profile first.
6. Only after algorithm-level acceptance should formal module validation be
   considered.

## D. Federal/FIPS note

A SABLE-only module is not currently a FIPS-approved primitive. A product could
contain SABLE as experimental/non-approved functionality, but any FIPS claim
must be scoped to approved algorithms and validated modules only.

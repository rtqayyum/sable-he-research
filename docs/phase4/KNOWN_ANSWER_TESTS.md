# Known-answer tests

Phase 4 adds deterministic known-answer vectors (KATs). They are intended to catch accidental API, serialization, and arithmetic regressions across releases.

The bundled KAT categories are:

1. `arithmetic_kat.json` — encrypted addition, subtraction, negation, scalar multiplication, multiplication, square, a quadratic expression, and Boolean gates encoded over the finite field.
2. `federated_learning_kat.json` — encrypted FedAvg over fixed-point model-weight arrays.
3. `pqc_envelope_kat.json` — deterministic envelope round-trip using the deliberately non-secure demo provider.
4. `cryptanalysis_kat.json` — deterministic cryptanalysis known-answer vector plus attack-surface report digest.

Generate a fresh bundle:

```bash
sable-he kat-generate --output tmp_kats
```

Verify the shipped bundle:

```bash
sable-he kat-verify vectors/phase4
```

KATs are engineering artifacts only. They do not establish cryptographic security.

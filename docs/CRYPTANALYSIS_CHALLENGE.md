# SABLE-HE Cryptanalysis Challenge

SABLE-HE Research is released to invite independent cryptanalysis and parameter review.

## Target surfaces

Reviewers are encouraged to analyze:

1. sparse q-ary LPN input encryption;
2. sparse-LPN GSW-style expansion key;
3. q-ary code/LPN coordinate compaction key;
4. public sample counts and multi-sample distinguishers;
5. low-noise correctness/security tension;
6. attacks on fixed-point encrypted FedAvg workflows;
7. API misuse and side-channel behavior.

## Reports we want

- proof gaps;
- concrete distinguishers;
- parameter-estimation improvements;
- better BKW/ISD-style cost models;
- correctness-failure attacks;
- serialization or randomness vulnerabilities;
- benchmark comparisons with OpenFHE, SEAL, TFHE-rs, or Concrete.

## Suggested report format

```text
Title:
Affected version/commit:
Affected parameter set:
Attack model:
Summary:
Steps to reproduce:
Expected impact:
Suggested mitigation:
References:
```

## Safe disclosure

Please use GitHub private vulnerability reporting or request a private channel before posting exploit-level details. General research critiques and non-exploit parameter comments may be opened as public issues.

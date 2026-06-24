# External FHE baselines

Phase 9 targets the following external baselines:

| Backend | Natural schemes | Natural workloads |
|---|---|---|
| OpenFHE | BFV, BGV, CKKS, FHEW, TFHE-like | exact arithmetic, approximate arithmetic, Boolean/function evaluation |
| Microsoft SEAL | BFV, BGV, CKKS | exact modular arithmetic and approximate arithmetic |
| TFHE-rs | TFHE | Boolean, short-integer, and integer circuits |
| Concrete | TFHE compiler | compiled FHE programs from Python-like functions |
| Lattigo | BFV/BGV-style, CKKS | Go-based exact and approximate HE baselines |

SABLE-HE documentation must distinguish measured SABLE timings from external measured timings. It is scientifically acceptable to ship templates before external measurements; it is not acceptable to fabricate external wall-clock numbers.

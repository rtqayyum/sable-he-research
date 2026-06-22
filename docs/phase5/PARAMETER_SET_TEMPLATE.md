# Parameter Set Template

Candidate parameters must state:

- `q`, `n`, `k`, `eta` for sparse q-ary LPN;
- public sparse-LPN sample count;
- `n_c`, `m_c`, `eta_c`, and code family for compaction;
- intended multiplicative depth and addition budget;
- correctness failure target;
- external attack-cost estimates for sparse-LPN, q-ary LPN, ISD/BKW, and low-noise attacks;
- implementation and side-channel assumptions.

The bundled presets remain research/test presets unless external cryptanalysis explicitly supports a security claim.

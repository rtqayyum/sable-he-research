# Premium references used for SABLE-HE validation context

This validation package intentionally uses primary or near-primary references.

1. Henry Corrigan-Gibbs, Alexandra Henzinger, Yael Tauman Kalai, Vinod Vaikuntanathan, **Somewhat Homomorphic Encryption from Linear Homomorphism and Sparse LPN**, IACR ePrint 2024/1760; EUROCRYPT 2025. This is the closest direct foundation: sparse-LPN SHE from sparse LPN plus a linearly homomorphic encryption component.

2. Sebastian Bitzer, Maximilian Egger, Mumin Liu, Antonia Wachter-Zeh, **Post-Quantum Secure Aggregation via Code-Based Homomorphic Encryption**, arXiv:2601.13031, 2026. This gives a current code/LPN homomorphic-encryption direction for aggregation and q-ary LPN-style constructions.

3. Dana Dachman-Soled, Huijing Gong, Hunter Kippen, Aria Shahverdi, **BKW Meets Fourier: New Algorithms for LPN with Sparse Parities**, IACR ePrint 2021/994. This is included as an attack-surface reference for sparse-LPN/BKW-style cryptanalysis.

4. Thom Wiggers and Simona Samardjiska, **Practically Solving LPN**, IACR ePrint 2021/962. This is included for practical LPN-attack context.

5. HomomorphicEncryption.org, **Security Guidelines for Implementing Homomorphic Encryption**, community security guidelines and toolkit. SABLE-HE is not lattice HE, but the validation discipline follows the same style: explicit parameters, correctness bounds, security-estimator notes, and conservative claims.


## Additional estimator and benchmark references

- Blum, Kalai, and Wasserman, "Noise-Tolerant Learning, the Parity Problem,
  and the Statistical Query Model."  Foundational BKW/LPN attack reference.
- Prange, "The Use of Information Sets in Decoding Cyclic Codes."  Classical
  information-set decoding idea.
- Becker, Joux, May, and Meurer, "Decoding Random Binary Linear Codes in
  2^(n/20)."  Modern ISD improvement and useful cryptanalytic reference.
- OpenFHE documentation and OpenFHE Python wrapper.  Baseline target for
  BFV, BGV, CKKS, FHEW, and TFHE-style measurements.

# Existing-method comparison notes

SABLE-HE-C5 should be compared by workload class, not by generic FHE slogans.

- TFHE/FHEW-style schemes are the closest baseline for Boolean gates and
  table/function evaluation.  Count bootstrapped Boolean gates or PBS calls.
- BFV/BGV are the closest baselines for exact modular/integer arithmetic.
  Count ciphertext additions, ciphertext multiplications, relinearization,
  modulus switching, and multiplicative depth.
- CKKS is a baseline for approximate real/complex arithmetic, not exact
  finite-field outputs.
- OpenFHE is the practical benchmarking target because it includes BFV, BGV,
  CKKS, FHEW/TFHE-like Boolean schemes, and hybrid/scheme-switching examples.
- Microsoft SEAL is a strong exact/approximate arithmetic baseline for BFV,
  BGV, and CKKS.
- Zama Concrete is a useful TFHE compiler/runtime baseline for programmable
  bootstrapping workloads.

The C5 package emits proxy counts now.  Actual optimized measurements should
be added only after compiling the external libraries under a fixed machine,
compiler, security level, and parameter policy.

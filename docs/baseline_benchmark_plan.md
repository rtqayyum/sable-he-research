
# Baseline benchmark plan

The validation package now includes `src/sable/baselines.py` and
`experiments/run_baseline_model.py`.  These produce operation-count proxy
tables; they do not claim measured TFHE, FHEW, BFV, BGV, or CKKS timings.

## Fair baseline categories

- **TFHE/FHEW-style Boolean evaluation:** compare Boolean circuits such as
  AND trees, OR formulas, and small binary classifiers.  Count programmable
  bootstraps or Boolean gates, then measure actual runtime in a concrete
  library.
- **BFV/BGV exact arithmetic:** compare finite-field or modular arithmetic
  circuits of the same multiplicative depth.
- **CKKS approximate arithmetic:** include only as context for approximate
  real-valued workloads; it is not a correctness-equivalent baseline for
  exact finite-field SABLE-HE.

## Optional harness

`experiments/openfhe_benchmark_harness.py` is a placeholder for an external
OpenFHE environment.  It intentionally does not vendor OpenFHE or make
network installations.  The next external step is to implement the same
workloads from the proxy table in OpenFHE BFV/BGV and FHEW/TFHE modes.

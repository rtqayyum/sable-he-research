# v0.12.0

- Security: sparse-LPN-specific screens and executable attacks (`sable.sparse_attacks`). Toy presets now warn (`InsecureParametersWarning`). The k<=2 candidate rows are rejected. New k=5/6 review rows. See docs/SECURITY_STATUS.md.
- Related work: positioned as an LPN-only instantiation of Corrigan-Gibbs, Henzinger, Kalai and Vaikuntanathan (EUROCRYPT 2025).
- Fast kernels: `sable.fast_regev` (key-additive secure aggregation) and `sable.fast_she` (vectorized SHE with seeded keys).
- Experiments: `experiments/` crypto and FL tracks, resumable runner, Slurm launcher (`scripts/hpc/`, docs/HPC_RUNBOOK.md).
- Fixes: `examples/attack_estimator.py` crash; README rewritten.

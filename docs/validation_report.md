# SABLE-HE validation report v2

## Current status

The repository contains a runnable research prototype for the SABLE-HE candidate:

- sparse-LPN Regev-style input encryption;
- sparse-LPN GSW-style expansion and homomorphic addition/multiplication;
- q-ary code/LPN linearly homomorphic compaction;
- correctness, size, and conservative failure-bound estimation;
- sparse-LPN/q-ary-LPN attack-screening models;
- benchmark-proxy and OpenFHE/TFHE baseline-planning scaffolds.

This is still a **validation prototype**, not production cryptography and not a certified parameter set.

## Test result

Command:

```bash
python -m pytest -q
```

Observed result:

```text
21 passed
```

Full output is in `docs/test_output.txt`.

## Main v2 finding

The attack screens identify a serious correctness/security tension:

- the homomorphic-error bound prefers very low sparse-LPN noise;
- low noise makes clean-subset and Prange/ISD-style screens cheap;
- the repetition-code CLPN compactor creates many row-difference samples, which makes the compaction key especially sensitive to low-noise analysis;
- all built-in presets are therefore **research-only** and should not be presented as cryptographic parameter sets.

## Estimator snapshot: candidate_depth1_rough

For `candidate_depth1_rough`, depth 1, additions 1:

```text
Fresh quality:     w=16 eps=0.00488281
Evaluated quality: w=256 eps=0.0830078
Compaction B=256 eta_B=0.015504
Per-replica failure bound: 0.0830078
Final replicated failure bound: 6.42201e-07
Security screen min bits: 0.09017119184795394
Passes screening target: False
```

Interpretation: correctness is plausible for a depth-1 toy/prototype workload, but the attack screen rejects it decisively.

## Security-feasibility grid snapshot

`docs/security_feasibility_grid.csv` records the conservative clean-subset dimension requirement induced by the correctness eta ceiling.  For example, at depth 1:

```text
k=1 eta_max/2=0.0125      required_n_clean_subset=7054
k=2 eta_max/2=0.00555556  required_n_clean_subset=15926
k=3 eta_max/2=0.003125    required_n_clean_subset=28347
```

At depth 2 and beyond, the required dimensions become very large under the current worst-case correctness bound.  This suggests that the next scientific target should be a better compaction layer and sharper distributional error analysis, not packaging a public library yet.

## Benchmarking status

The package now contains:

- `experiments/run_benchmark_proxy.py` for timing the pure-Python prototype;
- `experiments/run_baseline_proxy.py` for symbolic SABLE-vs-TFHE/FHEW operation-count comparisons;
- `experiments/openfhe_benchmark_harness.py` and `benchmarks/benchmark_boolean.py` as baseline scaffolds.

These are planning tools.  They are not optimized implementation benchmarks.

## Immediate next research tasks

1. Replace the repetition-code CLPN compactor with a stronger q-ary code/CRT-packed compactor.
2. Replace the screen estimator with a specialist sparse-LPN/q-ary-LPN estimator.
3. Add measured OpenFHE FHEW/TFHE Boolean-gate baselines.
4. Rework the proof to use distributional row-support/error bounds rather than only worst-case union bounds.
5. Update the LaTeX paper with the v2 negative finding: the initial all-code design is coherent, but naive compaction is the bottleneck.

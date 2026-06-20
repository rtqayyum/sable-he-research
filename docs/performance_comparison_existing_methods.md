# Performance comparison against existing HE methods: current status

## What was actually measured

The current package measures SABLE-C4 only, using the pure-Python research prototype and toy clean parameters. The measured operations include addition, subtraction, negation, scalar/plain operations, multiplication, square, powers, nonzero inversion/division, and Boolean gates encoded as polynomials.

The results are in:

- `docs/arithmetic_microbench_c4_toy_clean.csv`
- `docs/arithmetic_microbench_c4_toy_clean.json`
- `docs/arithmetic_microbench_c4_toy_clean.txt`

## What was not measured

OpenFHE, Microsoft SEAL, and TFHE-rs are not installed in this container, so the package does not report fake wall-clock timings for those libraries.

## Fair baseline mapping

| Workload | Best external baseline | Why |
|---|---|---|
| Boolean gates and bit circuits | TFHE/FHEW/OpenFHE BinFHE/TFHE-rs | Gate bootstrapping and Boolean/integer APIs are designed for this. |
| Exact small-modulus arithmetic | BFV/BGV in OpenFHE or SEAL | Exact modular arithmetic is their target. |
| Approximate real arithmetic | CKKS in OpenFHE or SEAL | CKKS is designed for approximate real/complex arithmetic. |
| Low-degree finite-field arithmetic under code/LPN assumptions | SABLE-C4 candidate | This is the proposed novelty and target niche. |

## Interpretation

SABLE-C4's prototype performance is not competitive evidence yet. Its scientific value, if it survives cryptanalysis, is assumption diversification: it avoids RLWE/MLWE and instead explores sparse-LPN plus q-ary code/LPN compaction.

The next empirical step is to run the same operation suite against OpenFHE BFV/BGV and TFHE/FHEW, and optionally TFHE-rs, on the same host.

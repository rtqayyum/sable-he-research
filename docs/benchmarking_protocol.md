# SABLE-HE benchmarking protocol

This repository now includes a first benchmark harness:

```bash
python benchmarks/benchmark_boolean.py --preset toy_noisy --gate and --trials 20
python benchmarks/benchmark_boolean.py --preset toy_noisy --gate xor --trials 20 --csv-output docs/bench_xor.csv
```

The harness measures the Python validation prototype only. It should not be
compared directly to optimized C/C++ libraries. Its purpose is to identify
SABLE-HE bottlenecks:

- input encryption and expansion;
- sparse matrix multiplication;
- compaction;
- final decoding;
- row-support and nonzero growth.

## Fair external baselines

For a paper, compare only against matching workloads:

| SABLE-HE workload | Fair baseline |
|---|---|
| low-depth Boolean gates | TFHE/FHEW gate bootstrapping |
| exact small-field arithmetic | BFV/BGV |
| approximate real arithmetic | CKKS as a comparison point only |
| secure aggregation/private counting | LPN/code-based secure aggregation |

## Required metrics

- parameter set;
- security estimate and estimator version;
- public evaluation-key size;
- input ciphertext size;
- expanded ciphertext size;
- final compact ciphertext size;
- key generation time;
- encryption/expansion time;
- evaluation time;
- compaction/decryption time;
- observed failure rate;
- maximum row support and total nonzeros.

## Next external benchmark step

Add optional adapters for one or more installed libraries:

- OpenFHE for BFV/BGV/CKKS/FHEW-style baselines;
- concrete-python or another TFHE-family toolchain where available;
- a simple JSON/CSV import path for externally produced TFHE results.

The current benchmark is a scaffold for those comparisons.

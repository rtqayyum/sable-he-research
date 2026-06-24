# Phase 9: Benchmark comparison framework

Phase 9 adds a reproducible benchmark framework for comparing SABLE-HE with external homomorphic-encryption systems on identical workloads.

The package measures the SABLE-HE Python reference implementation directly and produces templates for external libraries. External OpenFHE, Microsoft SEAL, TFHE-rs, Concrete, and Lattigo timings must be generated separately on the same hardware. Missing external values must never be filled in by proxy or guesswork.

## Workloads

The canonical workload set is:

- encrypted scalar addition;
- encrypted scalar multiplication;
- encrypted squaring;
- Boolean AND and XOR encoded over a prime field;
- length-4 dot product;
- degree-2 quadratic feature interaction;
- encrypted FedAvg over three clients and three weights.

## Metrics

For each backend, collect:

- key-generation time;
- encryption time;
- evaluation time;
- compaction/decryption time, where applicable;
- public/evaluation key size;
- ciphertext size;
- memory use, when available;
- parameter/security description.

## CLI

```bash
sable-he benchmark-info
sable-he benchmark-workloads
sable-he benchmark-sable --preset c7_standard_toy_clean --repetitions 3 --output sable_bench.json
sable-he benchmark-package --output phase9_benchmark_package
sable-he benchmark-baseline-template --output external_baselines.json
```

## External baselines

The benchmark package includes a baseline protocol and a JSON template for external results. The paper should cite externally measured rows only after those rows are generated on the same machine under the same workload definitions.

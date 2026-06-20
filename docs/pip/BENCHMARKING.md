# Benchmarking Guide

The package contains local toy benchmarks and proxy comparison material. It does not include optimized external FHE libraries.

## Local toy benchmark examples

Run the included benchmark scripts from the project root:

```bash
python benchmarks/benchmark_arithmetic.py
python benchmarks/benchmark_boolean.py
```

Run experiment scripts:

```bash
python experiments/run_c5_arithmetic_suite.py
python experiments/run_c5_compare_baselines.py
python experiments/run_c6_relation_estimator.py
```

## What the local benchmarks measure

- Python-level prototype timing.
- Operation support.
- Correctness under toy presets.
- Size and operation-count proxies.
- Relation-surface diagnostics.

## What they do not measure

- Optimized C++/Rust FHE library performance.
- Constant-time or cache behavior.
- Production serialization overhead.
- Hardware acceleration.

## External baselines to add later

For a serious comparison, run identical circuits against:

- TFHE/FHEW-style Boolean HE implementations for Boolean gate workloads;
- BFV/BGV implementations for exact arithmetic;
- CKKS implementations for approximate arithmetic.

The fair comparison should report parameter choices, circuit depth, ciphertext sizes, key sizes, wall-clock timings, memory, and failure probability.

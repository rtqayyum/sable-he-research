# SABLE-HE CLI reference

The package installs a command-line tool:

```bash
sable-he
```

## Version and status

```bash
sable-he --version
sable-he version
sable-he info
sable-he readiness
```

## List presets

```bash
sable-he presets
sable-he presets --json
```

## End-to-end demo

Two equivalent styles are supported.

```bash
sable-he demo --operation mul --x 3 --y 5 --preset c7_standard_toy_clean
sable-he run mul --x 3 --y 5 --preset c7_standard_toy_clean
```

Supported toy operations:

```text
add, sub, neg, scalar3, mul, square, pow3,
not, and, or, xor, nand, nor, xnor, implies
```

Examples:

```bash
sable-he demo --operation add --x 2 --y 4
sable-he demo --operation sub --x 2 --y 4
sable-he demo --operation neg --x 2
sable-he demo --operation scalar3 --x 3
sable-he demo --operation square --x 3
sable-he demo --operation pow3 --x 3
sable-he demo --operation xor --x 1 --y 1
sable-he demo --operation not --x 0
```

Use JSON output:

```bash
sable-he demo --operation mul --x 3 --y 5 --json
sable-he run xor --x 1 --y 0 --json
```

## Quickstart command

```bash
sable-he quickstart
sable-he quickstart --x 3 --y 5 --preset c7_standard_toy_clean
```

This runs a deterministic encrypted multiplication demo.

## Correctness/size/security-screen estimator

```bash
sable-he estimate --preset c7_standard_toy_noisy --depth 1 --additions 1
sable-he estimate --preset c7_standard_toy_noisy --depth 1 --additions 1 --json
```

## C7 relation screen

```bash
sable-he screen-c7 --preset c7_standard_toy_noisy
sable-he screen-c7 --preset c7_standard_toy_noisy --json
```

Optional settings:

```bash
sable-he screen-c7 --mode standard --block-size 3 --relation-screen-weight 3
sable-he screen-c7 --mode screened-random --basis-size 5 --max-terms-per-block 2
```

## Baseline proxy comparison

```bash
sable-he baselines --preset c7_standard_toy_noisy
sable-he compare --preset c7_standard_toy_noisy
sable-he baselines --preset c7_standard_toy_noisy --json
```

These are symbolic/proxy comparisons. They are not optimized-library wall-clock benchmarks.

## Self-test

```bash
sable-he self-test
```

The self-test runs a small fixed collection of toy arithmetic/Boolean operations.

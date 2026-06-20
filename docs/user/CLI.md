# CLI Reference

The package installs the `sable-he` command.

## `sable-he version`

Prints package version and status.

## `sable-he presets`

Lists bundled toy and research parameter presets.

Options:

```bash
sable-he presets --json
```

## `sable-he quickstart`

Runs encrypted multiplication on a toy C7 preset.

```bash
sable-he quickstart --x 3 --y 5
```

## `sable-he run OPERATION`

Runs one encrypted operation.

Supported operations:

```text
add sub neg scalar3 mul square and or xor nand nor xnor implies
```

Example:

```bash
sable-he run or --x 1 --y 0
```

## `sable-he estimate`

Runs the correctness/size/security screen.

```bash
sable-he estimate --preset c7_standard_toy_clean --depth 1 --additions 1
```

## `sable-he compare`

Prints a proxy comparison for balanced products and quadratic-form workloads.

```bash
sable-he compare --preset c7_standard_toy_clean
```

The output is an operation-count/proxy comparison, not measured OpenFHE/SEAL/TFHE-rs timing.

## `sable-he readiness`

Prints readiness gates. Production and certification gates remain red until independent cryptanalysis, hardened implementation, external audit, and stable parameters exist.

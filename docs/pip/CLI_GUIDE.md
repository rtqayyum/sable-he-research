# CLI Guide

The package installs the `sable-he` command.

## Show package information

```bash
sable-he info
```

## Run a toy encrypted operation

```bash
sable-he demo --operation mul --x 3 --y 5
sable-he demo --operation add --x 3 --y 5
sable-he demo --operation xor --x 1 --y 0
sable-he demo --operation square --x 3
sable-he demo --operation scalar3 --x 3
```

Use JSON output:

```bash
sable-he demo --operation mul --x 3 --y 5 --json
```

## Run a parameter estimate

```bash
sable-he estimate --preset c7_standard_toy_clean --depth 1
```

JSON output:

```bash
sable-he estimate --preset c7_standard_toy_clean --depth 1 --json
```

## Run a quick self-test

```bash
sable-he self-test
```

This checks a small set of encrypted operations end to end under toy parameters.

## CLI status line

The CLI deliberately prints that outputs are toy validation results. This is part of the security boundary: the package is a research artifact, not production cryptography.

# Installation Guide

This guide explains how to install the SABLE-HE research package locally.

## Requirements

- Python 3.10 or newer.
- `pip`.
- No runtime third-party dependency is required for the core package.
- `pytest` is needed only for the test suite.

## Install the prebuilt wheel

From the project root after unpacking the package ZIP:

```bash
python -m pip install dist/sable_he_research-0.1.0-py3-none-any.whl
```

Verify:

```bash
sable-he info
sable-he self-test
```

## Install from source

```bash
python -m pip install .
```

## Editable development install

```bash
python -m pip install -e ".[dev]"
pytest
```

## Build the wheel yourself

```bash
python -m pip wheel . --no-deps --no-build-isolation -w dist
```

The generated wheel appears under `dist/`.

## Uninstall

```bash
python -m pip uninstall sable-he-research
```

## Common problems

### `sable-he: command not found`

Run:

```bash
python -m pip show sable-he-research
```

If the package is installed but the command is not available, your Python scripts directory may not be on `PATH`. You can still run:

```bash
python -m sable.cli info
```

### Import works from source but not after install

Use a clean shell and verify the active Python interpreter:

```bash
python -c "import sys; print(sys.executable)"
python -c "import sable; print(sable.__version__)"
```

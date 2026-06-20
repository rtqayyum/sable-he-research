# Installation Guide

## Supported Python versions

The package requires Python 3.10 or newer.

## Install from wheel

After downloading or building the project, install the wheel:

```bash
python -m pip install dist/sable_he_research-0.1.0-py3-none-any.whl
```

Verify the command-line interface:

```bash
sable-he version
sable-he quickstart
```

## Install from source

From the project root:

```bash
python -m pip install .
```

For editable development:

```bash
python -m pip install -e .[dev]
python -m pytest
```

## Build distributions

```bash
python -m pip wheel . --no-deps -w dist
python setup.py sdist  # only if a setup.py is added; otherwise use python -m build
```

This package uses `pyproject.toml` and setuptools as the build backend.

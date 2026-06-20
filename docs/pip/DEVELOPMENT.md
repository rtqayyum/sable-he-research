# Development Guide

## Editable install

```bash
python -m pip install -e ".[dev]"
pytest
```

## Run the CLI from source

```bash
PYTHONPATH=src python -m sable.cli info
PYTHONPATH=src python -m sable.cli self-test
```

## Build wheel

```bash
rm -rf build dist src/*.egg-info
python -m pip wheel . --no-deps --no-build-isolation -w dist
```

## Repository layout

```text
src/sable/        package code
tests/            pytest suite
examples/         simple usage examples
experiments/      research scripts
docs/             reports and documentation
benchmarks/       microbenchmark scripts
paper/            manuscript files
vectors/          toy KAT vectors
```

## Release checklist

1. Run `pytest`.
2. Run `sable-he self-test` after installing the wheel.
3. Run at least one estimator command.
4. Verify examples under `examples/`.
5. Rebuild `dist/`.
6. Zip the repository and wheel together.

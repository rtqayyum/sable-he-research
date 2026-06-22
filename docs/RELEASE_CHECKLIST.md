# GitHub and PyPI Release Checklist

## Before tagging

```bash
python -m pip install -e ".[dev,numpy]"
python -m pytest -q
python -m build
python -m twine check dist/*
```

## Tag and push

```bash
git status
git add .
git commit -m "Prepare public research release v0.2.1"
git tag v0.2.1
git push origin main
git push origin v0.2.1
```

## Upload to PyPI from terminal

```bash
python -m pip install --upgrade build twine
rm -rf dist build *.egg-info src/*.egg-info
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Use username `__token__` and paste your PyPI API token as the password.

## GitHub release

On GitHub, create a release from tag `v0.2.1`. Attach:

- wheel file;
- source distribution;
- final manuscript PDF if desired;
- short release notes.

## Post-release validation

```bash
python -m pip install --upgrade sable-he-research
sable-he --version
sable-he fl-demo
sable-he fl-capabilities
```

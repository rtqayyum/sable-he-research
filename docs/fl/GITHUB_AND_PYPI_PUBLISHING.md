# GitHub and PyPI publishing guide

This repository is prepared for normal GitHub and PyPI release flow.

## 1. Create a GitHub repository

```bash
git init
git add .
git commit -m "Initial SABLE-HE FL package"
git branch -M main
git remote add origin git@github.com:<YOUR-USER-OR-ORG>/sable-he-research.git
git push -u origin main
```

## 2. Run tests locally

```bash
python -m pip install -e .[dev,numpy]
python -m pytest -q
sable-he fl-demo
```

## 3. Build distributions locally

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
```

If `build` is unavailable, the included `setup.py` compatibility shim also supports:

```bash
python setup.py sdist bdist_wheel
```

## 4. Recommended PyPI release path: Trusted Publishing

The included workflow `.github/workflows/publish-pypi.yml` is designed for PyPI Trusted Publishing. After creating the PyPI project, configure a trusted publisher for:

- repository owner/name
- workflow file: `publish-pypi.yml`
- environment: `pypi`

Then tag a release:

```bash
git tag v0.2.0
git push origin v0.2.0
```

GitHub Actions will build and publish using PyPI's OIDC trusted-publishing flow.

## 5. Token-based fallback

If you cannot use trusted publishing, create a PyPI API token and upload manually:

```bash
python -m twine upload dist/*
```

Use TestPyPI first for a dry run.

## 6. Naming note

The distribution name is:

```text
sable-he-research
```

The import name is:

```python
import sable
```

# GitHub and PyPI release guide

This guide describes how to publish the package source to GitHub and upload distributions to PyPI.

## 1. Prepare the local package

```bash
python -m pip install -e .[dev,numpy]
python -m pytest -q
python -m build
python -m twine check dist/*
```

The build step creates:

```text
dist/sable_he_research-0.2.0-py3-none-any.whl
dist/sable_he_research-0.2.0.tar.gz
```

## 2. Create a GitHub repository

Using GitHub CLI:

```bash
git init
git add .
git commit -m "Initial SABLE-HE release"
gh repo create YOUR_GITHUB_USER/sable-he --public --source=. --remote=origin --push
```

Without GitHub CLI:

```bash
git init
git add .
git commit -m "Initial SABLE-HE release"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USER/sable-he.git
git push -u origin main
```

## 3. TestPyPI dry run

Create an API token on TestPyPI, then run:

```bash
python -m twine upload --repository testpypi dist/*
```

Install from TestPyPI in a clean environment:

```bash
python -m venv /tmp/sable-test
source /tmp/sable-test/bin/activate
python -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ sable-he-research
sable-he fl-demo
```

## 4. PyPI release

Create a PyPI API token and upload:

```bash
python -m twine upload dist/*
```

Then verify:

```bash
python -m venv /tmp/sable-pypi
source /tmp/sable-pypi/bin/activate
python -m pip install sable-he-research
sable-he --version
sable-he fl-demo
```

## 5. Recommended GitHub release checklist

- Tag the release:

```bash
git tag v0.2.0
git push origin v0.2.0
```

- Create a GitHub release from the tag.
- Attach the wheel and source distribution.
- Include release notes from `RELEASE_NOTES_v0.2_FL.md`.
- Keep `SECURITY.md` visible at repository root.
- Pin future release versions in `pyproject.toml` and `src/sable/version.py`.

## 6. Optional trusted publishing

For a long-term project, configure PyPI Trusted Publishing with GitHub Actions rather than manually storing PyPI tokens. Keep manual token upload only for the first local release or emergency releases.

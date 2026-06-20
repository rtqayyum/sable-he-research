# Publishing SABLE-HE to GitHub and PyPI

This guide assumes the package directory contains `pyproject.toml`, `README.md`, `LICENSE`, `src/sable`, `tests`, `docs`, and built artifacts under `dist/`.

## 1. Run tests

```bash
python -m pip install -e .[dev,numpy]
python -m pytest -q
sable-he fl-demo
sable-he fl-capabilities
```

## 2. Build wheel and source distribution

```bash
python -m build --wheel --sdist
```

This creates files such as:

```text
dist/sable_he_research-0.2.0-py3-none-any.whl
dist/sable_he_research-0.2.0.tar.gz
```

## 3. Check package metadata

```bash
python -m twine check dist/*
```

## 4. Test upload to TestPyPI

```bash
python -m twine upload --repository testpypi dist/*
```

Install from TestPyPI in a fresh environment:

```bash
python -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ sable-he-research
```

## 5. Upload to PyPI

```bash
python -m twine upload dist/*
```

PyPI project names are global. If `sable-he-research` is unavailable, choose another name in `pyproject.toml`, rebuild, and upload again.

## 6. Create a GitHub repository

Using GitHub CLI:

```bash
git init -b main
git add .
git commit -m "Initial public release with FL aggregation API"
gh repo create sable-he-research --public --source=. --remote=origin --push
```

Using the web UI: create a new repository, do not initialize it with another README, then push:

```bash
git remote add origin git@github.com:YOUR_USERNAME/sable-he-research.git
git push -u origin main
```

## 7. Suggested repository description

```text
SABLE-HE: code/LPN-based homomorphic-encryption research package with encrypted arithmetic and federated-learning aggregation utilities.
```

## 8. Suggested release checklist

- [ ] Tests pass locally.
- [ ] `sable-he fl-demo` works.
- [ ] README includes security status and FL examples.
- [ ] `twine check dist/*` passes.
- [ ] TestPyPI install succeeds.
- [ ] GitHub repository has README, LICENSE, SECURITY.md, docs, examples, and CI.
- [ ] Tag release: `git tag v0.2.0 && git push origin v0.2.0`.
- [ ] Upload to PyPI.

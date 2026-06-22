# Release engineering

Recommended release sequence:

```bash
python -m pytest -q
sable-he self-test
sable-he fl-demo
sable-he pqc-demo
sable-he cryptanalysis-info
sable-he kat-verify vectors/phase4
sable-he repo-hygiene .
sable-he release-check .

rm -rf dist build *.egg-info src/*.egg-info
python -m build
python -m twine check dist/*
python -m twine upload dist/sable_he_research-<VERSION>*
```

Do not run `twine upload dist/*` if old versions are still present in `dist/`, because PyPI files are immutable.

Before pushing a public release, run:

```bash
git ls-files | egrep '^(paper|audits|experiments|benchmarks|docs/generated)|\.pdf$' || echo "clean"
```

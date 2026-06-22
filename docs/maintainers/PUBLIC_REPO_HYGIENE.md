# Public Repository Hygiene

Do not commit private research drafts or generated internal artifacts to the public repository.

## Keep public

- `src/`
- `tests/`
- `examples/`
- selected `docs/` guides
- `.github/` issue templates and CI workflows
- `pyproject.toml`, `README.md`, `LICENSE`, `SECURITY.md`, `CITATION.cff`

## Keep private / do not commit

- `paper/`
- LaTeX source, compiled PDFs, rendered pages
- `audits/`
- `experiments/` raw scratch outputs
- `docs/generated/`
- build artifacts such as `dist/`, `build/`, `*.egg-info`
- old validation logs, screenshots, temporary notebooks

Use the clean release ZIP as the source for public GitHub updates.

# SABLE-HE LaTeX project

This folder contains a research-draft LaTeX manuscript for **SABLE-HE: A Sparse-LPN and Code-LPN Candidate for All-Code-Based Leveled Homomorphic Encryption**.

## Files

- `main.tex` - root manuscript file.
- `macros.tex` - packages, theorem environments, and notation.
- `sections/` - main paper sections.
- `appendices/` - proof appendix, pseudocode, and review checklist.
- `references.bib` - BibTeX bibliography with peer-reviewed and primary-source references.
- `Makefile` - simple build and clean commands.

## Build

Run:

```bash
make
```

The Makefile uses `pdflatex` and `bibtex8`, which works in this build environment. On systems with a normal BibTeX installation, `latexmk -pdf main.tex` should also work.

To clean auxiliary files:

```bash
make clean
```

## Research status

This is a candidate construction. It contains a formal design and proof sketch under sparse-LPN and q-ary LPN/code assumptions, but it does not certify concrete secure parameters. Before publication or implementation claims, add:

1. a parameter estimator,
2. independent cryptanalysis,
3. empirical failure-rate experiments,
4. benchmark comparison against TFHE/FHEW and BFV/BGV/CKKS baselines.

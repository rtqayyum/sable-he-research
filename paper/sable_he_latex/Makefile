PDF=main.pdf

all:
	pdflatex -interaction=nonstopmode main.tex
	bibtex8 main
	pdflatex -interaction=nonstopmode main.tex
	pdflatex -interaction=nonstopmode main.tex

clean:
	rm -f *.aux *.bbl *.blg *.fls *.fdb_latexmk *.log *.out *.toc *.run.xml *.bcf sections/*.aux appendices/*.aux

distclean: clean
	rm -f $(PDF)

.PHONY: all clean distclean

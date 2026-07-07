# Documentation

Typeset reference and exploitation guide for every planted vulnerability.

## Contents

- **`vulnerabilities.pdf`** — compiled guide: overview, summary table, and one
  section per planted vulnerability (location, planted sink, what it is,
  exploitation variants, remediation).
- **`vulnerabilities.tex`** — LaTeX source for the PDF (auto-generated).
- **`cwe_kb.py`** — knowledge base: per-CWE explanation, exploitation variants,
  and remediation. Edit this to improve the prose.
- **`build_docs.py`** — generator: reads `../reference.sarif` + `cwe_kb.py`,
  writes `vulnerabilities.tex` and refreshes `../VULNERABILITIES.md`.

The data (which vuln, which file/line, which snippet) always comes from
`reference.sarif` — the single source of truth — so the docs stay in sync with
the fixture.

## Rebuilding

```bash
# from the project root
python3 docs/build_docs.py                 # regenerate .tex + VULNERABILITIES.md

# compile the PDF (run twice so the ToC / long table resolve)
pdflatex -interaction=nonstopmode -output-directory=docs docs/vulnerabilities.tex
pdflatex -interaction=nonstopmode -output-directory=docs docs/vulnerabilities.tex

# tidy LaTeX aux files
rm -f docs/*.aux docs/*.log docs/*.out docs/*.toc
```

### Toolchain

Requires a LaTeX distribution with `listings`, `xcolor`, `longtable`,
`booktabs`, `hyperref`, `fancyhdr`, `enumitem`. On Debian/Ubuntu:

```bash
sudo apt-get install -y --no-install-recommends \
  texlive-latex-base texlive-latex-recommended texlive-latex-extra \
  texlive-fonts-recommended lmodern
```

## Adding / editing explanations

1. Update the relevant `CWE-XXX` entry in `cwe_kb.py` (or add a new one).
2. Run `python3 docs/build_docs.py`.
3. Recompile the PDF (two `pdflatex` passes).

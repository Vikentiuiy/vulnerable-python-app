#!/usr/bin/env python3
"""
Generate project documentation from reference.sarif + cwe_kb.py.

Outputs (into docs/):
  - vulnerabilities.tex   : LaTeX source, one section per planted vulnerability
  - vulnerabilities.pdf   : compiled PDF (run pdflatex twice)
Also refreshes ../VULNERABILITIES.md with the full catalog table + details.

Usage:
  python3 docs/build_docs.py          # from project root
  pdflatex -output-directory=docs docs/vulnerabilities.tex   # x2 for TOC
"""
import json, os, sys, html

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from cwe_kb import KB  # noqa

SARIF = os.path.join(ROOT, "reference.sarif")


def load_vulns():
    d = json.load(open(SARIF))
    run = d["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    out = []
    for res in run["results"]:
        rid = res["ruleId"]
        rule = rules.get(rid, {})
        loc = res["locations"][0]["physicalLocation"]
        out.append({
            "vulnId": res["properties"].get("vulnId", "?"),
            "cwe": res["properties"].get("cwe", "?"),
            "ruleId": rid,
            "title": rule.get("shortDescription", {}).get("text", rid),
            "sev": rule.get("properties", {}).get("security-severity", "?"),
            "helpUri": rule.get("helpUri", ""),
            "file": loc["artifactLocation"]["uri"],
            "line": loc["region"]["startLine"],
            "snippet": loc["region"].get("snippet", {}).get("text", "").strip(),
            "msg": res["message"]["text"],
        })
    out.sort(key=lambda v: int(v["vulnId"].split("-")[1]) if "-" in v["vulnId"] else 0)
    return out


# ---------- LaTeX ----------
def tex_escape(s):
    repl = {'\\': r'\textbackslash{}', '&': r'\&', '%': r'\%', '$': r'\$',
            '#': r'\#', '_': r'\_', '{': r'\{', '}': r'\}',
            '~': r'\textasciitilde{}', '^': r'\textasciicircum{}'}
    return ''.join(repl.get(c, c) for c in s)


def build_tex(vulns):
    by_cwe = {}
    for v in vulns:
        by_cwe.setdefault(v["cwe"], 0)
        by_cwe[v["cwe"]] += 1
    L = []
    A = L.append
    A(r"\documentclass[11pt,a4paper]{article}")
    A(r"\usepackage[utf8]{inputenc}")
    A(r"\usepackage[T1]{fontenc}")
    A(r"\usepackage{lmodern}")
    A(r"\usepackage[margin=2.2cm]{geometry}")
    A(r"\usepackage{xcolor}")
    A(r"\usepackage{listings}")
    A(r"\usepackage{longtable}")
    A(r"\usepackage{booktabs}")
    A(r"\usepackage{enumitem}")
    A(r"\usepackage{fancyhdr}")
    A(r"\usepackage[hidelinks]{hyperref}")
    A(r"\definecolor{codebg}{RGB}{245,245,245}")
    A(r"\definecolor{vulnred}{RGB}{155,20,20}")
    A(r"\lstset{basicstyle=\ttfamily\small,breaklines=true,frame=single,"
      r"backgroundcolor=\color{codebg},columns=fullflexible,keepspaces=true,"
      r"showstringspaces=false,xleftmargin=4pt,framexleftmargin=4pt}")
    A(r"\pagestyle{fancy}\fancyhf{}")
    A(r"\lhead{Vulnerable Python App}\rhead{SAST Reference Catalog}")
    A(r"\cfoot{\thepage}")
    A(r"\title{\textbf{Vulnerable Python App}\\[4pt]\large Planted Vulnerability"
      r" Reference \& Exploitation Guide}")
    A(r"\author{SAST Benchmark Fixture}")
    A(r"\date{\today}")
    A(r"\begin{document}")
    A(r"\maketitle")
    A(r"\begin{center}\fbox{\parbox{0.9\textwidth}{\centering\bfseries"
      r" WARNING: This project is intentionally vulnerable. Never deploy, run,"
      r" or expose it in any real environment. It exists only to benchmark SAST"
      r" tools.}}\end{center}")
    A(r"\vspace{6pt}")
    A(r"\tableofcontents")
    A(r"\newpage")

    # Overview
    A(r"\section{Overview}")
    A(f"This catalog documents the \\textbf{{{len(vulns)}}} vulnerabilities "
      f"planted across \\textbf{{{len(by_cwe)}}} unique CWE classes in this "
      r"fixture. Each entry gives the location (as recorded in "
      r"\texttt{reference.sarif}), the planted sink, a plain-language "
      r"explanation, concrete exploitation variants, and remediation. "
      r"Every sink is marked in-source with a \texttt{\# VULN-XX} comment.")

    # Summary table
    A(r"\section{Summary table}")
    A(r"\renewcommand{\arraystretch}{1.15}")
    A(r"\begin{longtable}{@{}l l l r l@{}}")
    A(r"\toprule \textbf{ID} & \textbf{CWE} & \textbf{File} & \textbf{Line} &"
      r" \textbf{Sev} \\ \midrule \endhead")
    for v in vulns:
        A(f"{tex_escape(v['vulnId'])} & {tex_escape(v['cwe'])} & "
          f"\\texttt{{{tex_escape(os.path.basename(v['file']))}}} & "
          f"{v['line']} & {tex_escape(str(v['sev']))} \\\\")
    A(r"\bottomrule \end{longtable}")

    # Detailed entries
    A(r"\section{Vulnerability details}")
    for v in vulns:
        kb = KB.get(v["cwe"], {})
        head = f"{v['vulnId']}: {v['title']}"
        A(r"\subsection{" + tex_escape(head) + "}")
        A(r"\noindent\textbf{Location:} \texttt{" +
          tex_escape(v["file"]) + f"}}, line {v['line']} "
          r"\quad \textbf{Rule:} \texttt{" + tex_escape(v["ruleId"]) + "} "
          r"\quad \textbf{Severity:} " + tex_escape(str(v["sev"])))
        if v.get("helpUri"):
            A(r"\\ \textbf{Reference:} \url{" + v["helpUri"] + "}")
        A("")
        if v.get("snippet"):
            A(r"\noindent\textbf{Planted sink:}")
            A(r"\begin{lstlisting}")
            A(v["snippet"])
            A(r"\end{lstlisting}")
        if kb.get("what"):
            A(r"\noindent\textbf{What it is.} " + tex_escape(kb["what"]))
            A("")
        if kb.get("exploit"):
            A(r"\noindent\textbf{Exploitation variants.}")
            A(r"\begin{itemize}[leftmargin=1.4em,itemsep=1pt,topsep=2pt]")
            for e in kb["exploit"]:
                A(r"\item " + tex_escape(e))
            A(r"\end{itemize}")
        if kb.get("fix"):
            A(r"\noindent\textbf{Remediation.} " + tex_escape(kb["fix"]))
            A("")
        A(r"\vspace{4pt}\hrule\vspace{6pt}")

    A(r"\end{document}")
    return "\n".join(L)


# ---------- Markdown ----------
def build_md(vulns):
    by_cwe = {}
    for v in vulns:
        by_cwe.setdefault(v["cwe"], 0); by_cwe[v["cwe"]] += 1
    M = []
    A = M.append
    A("# Planted Vulnerabilities Catalog\n")
    A(f"Total planted vulnerabilities: **{len(vulns)}** across "
      f"**{len(by_cwe)}** unique CWEs.\n")
    A("> A richer, typeset version with exploitation notes lives in "
      "`docs/vulnerabilities.pdf` (source: `docs/vulnerabilities.tex`).\n")
    A("Each entry lists the vuln id, CWE, source file, sink line (as recorded "
      "in `reference.sarif`), and description.\n")
    A("| ID | CWE | File | Line |")
    A("|----|-----|------|------|")
    for v in vulns:
        A(f"| {v['vulnId']} | {v['cwe']} | `{os.path.basename(v['file'])}` "
          f"| {v['line']} |")
    A("\n## Details\n")
    for v in vulns:
        kb = KB.get(v["cwe"], {})
        A(f"### {v['vulnId']}: {v['title']}\n")
        A(f"- **Location:** `{v['file']}`, line {v['line']}")
        A(f"- **Rule:** `{v['ruleId']}` | **Severity:** {v['sev']}")
        if v.get("helpUri"):
            A(f"- **Reference:** {v['helpUri']}")
        if v.get("snippet"):
            A(f"\n```python\n{v['snippet']}\n```\n")
        if kb.get("what"):
            A(f"**What it is.** {kb['what']}\n")
        if kb.get("exploit"):
            A("**Exploitation variants.**")
            for e in kb["exploit"]:
                A(f"- {e}")
            A("")
        if kb.get("fix"):
            A(f"**Remediation.** {kb['fix']}\n")
    return "\n".join(M)


def main():
    vulns = load_vulns()
    missing = sorted({v["cwe"] for v in vulns} - set(KB))
    if missing:
        print("WARNING: no KB entry for:", missing, file=sys.stderr)
    tex = build_tex(vulns)
    open(os.path.join(HERE, "vulnerabilities.tex"), "w").write(tex)
    open(os.path.join(ROOT, "VULNERABILITIES.md"), "w").write(build_md(vulns))
    print(f"Wrote docs/vulnerabilities.tex and VULNERABILITIES.md "
          f"({len(vulns)} vulns, {len({v['cwe'] for v in vulns})} CWEs)")


if __name__ == "__main__":
    main()

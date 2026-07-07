#!/usr/bin/env python3
"""gen_docs.py — Generate VULNERABILITIES.md from reference.sarif.

Produces a human-readable catalog of every planted vulnerability: its id, CWE,
rule, exact file:line location and the sink snippet. Regenerate whenever
reference.sarif changes.

Usage:
  python3 gen_docs.py --reference reference.sarif --out VULNERABILITIES.md
"""

import argparse
import json
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", default="reference.sarif")
    ap.add_argument("--out", default="VULNERABILITIES.md")
    args = ap.parse_args()

    with open(args.reference, encoding="utf-8") as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = run["results"]

    rows = []
    by_cwe = defaultdict(int)
    for res in results:
        p = res["properties"]
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        line = loc["region"]["startLine"]
        snippet = loc["region"].get("snippet", {}).get("text", "")
        rule = rules.get(res["ruleId"], {})
        rname = rule.get("shortDescription", {}).get("text", res["ruleId"])
        rows.append({
            "vulnId": p["vulnId"],
            "cwe": p["cwe"],
            "rule": res["ruleId"],
            "rname": rname,
            "loc": f"{uri}:{line}",
            "msg": res["message"]["text"],
            "snippet": snippet,
        })
        by_cwe[p["cwe"]] += 1

    rows.sort(key=lambda r: int(r["vulnId"].split("-")[1]))

    lines = []
    lines.append("# Planted Vulnerabilities Catalog\n")
    lines.append("> Auto-generated from `reference.sarif` by `gen_docs.py`. "
                 "Do not edit by hand.\n")
    lines.append(f"**Total planted vulnerabilities:** {len(rows)}  ")
    lines.append(f"**Distinct CWEs:** {len(by_cwe)}\n")

    lines.append("## Summary by CWE\n")
    lines.append("| CWE | Count |")
    lines.append("| --- | ----- |")
    for cwe in sorted(by_cwe, key=lambda c: int(c.split("-")[1])):
        lines.append(f"| {cwe} | {by_cwe[cwe]} |")
    lines.append("")

    lines.append("## Full list\n")
    for r in rows:
        lines.append(f"### {r['vulnId']} — {r['cwe']}\n")
        lines.append(f"- **Rule:** `{r['rule']}` ({r['rname']})")
        lines.append(f"- **Location:** `{r['loc']}`")
        lines.append(f"- **Description:** {r['msg']}")
        lines.append(f"- **Sink:**\n")
        lines.append("  ```python")
        lines.append(f"  {r['snippet']}")
        lines.append("  ```\n")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Wrote {args.out}: {len(rows)} vulns, {len(by_cwe)} CWEs.")


if __name__ == "__main__":
    main()

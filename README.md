# Vulnerable Python App — SAST Test Fixture

⚠️ **WARNING: This project is intentionally vulnerable. Do NOT deploy or run it
in any production or internet-facing environment. It exists solely to benchmark
SAST (Static Application Security Testing) tools.**

## Purpose

A small Python project that intentionally implements **60** of the most common
software vulnerabilities (SQL injection, command injection, path traversal, XSS,
SSTI, weak crypto, SSRF, insecure deserialization, hardcoded secrets, XXE, etc.),
spanning **45 distinct CWEs**.

Intended workflow:

1. Zip up this project and submit it to a SAST tool.
2. The SAST tool returns a `SARIF` file describing the vulnerabilities it found.
3. Use `sast_checker.py` to compare the tool's SARIF output against the
   reference SARIF (`reference.sarif`) that describes the *known* planted
   vulnerabilities and their exact locations.

## Files

- `src/vulnapp/**` — vulnerable source code (6 modules, grouped by family).
- `reference.sarif` — ground-truth SARIF listing every planted vulnerability,
  its CWE, rule id, and exact file/line location.
- `sast_checker.py` — compares a tool-produced SARIF against `reference.sarif`
  and reports recall / precision / F1 + matched / missed / extra findings.
- `gen_reference.py` — regenerates `reference.sarif` from the in-source markers
  (guarantees line numbers never drift from the code).
- `gen_docs.py` — regenerates `VULNERABILITIES.md` from `reference.sarif`.
- `VULNERABILITIES.md` — human-readable catalog of every planted vulnerability.
- `requirements.txt` — libraries referenced by the sample code (not required to
  run the scan/compare workflow).

## Source layout

| Module | Vuln range | Theme |
| ------ | ---------- | ----- |
| `src/vulnapp/injection_vulns.py`    | VULN-01..11 | SQLi, command/code/LDAP/NoSQL injection, ReDoS |
| `src/vulnapp/web_vulns.py`          | VULN-12..19 | XSS, SSTI, open redirect, CORS, cookies, clickjacking |
| `src/vulnapp/file_network_vulns.py` | VULN-20..26 | Path traversal, SSRF, tar slip, temp files, pickle |
| `src/vulnapp/crypto_secret_vulns.py`| VULN-27..37 | Hardcoded secrets, weak hashes/ciphers, bad RNG |
| `src/vulnapp/auth_api_vulns.py`     | VULN-38..49 | AuthN/AuthZ, IDOR, JWT, rate limiting, error exposure |
| `src/vulnapp/data_config_vulns.py`  | VULN-50..60 | XXE, unsafe YAML, reflection, logging, TLS, upload |

## Vulnerability markers

Every planted vulnerability is tagged in-source with a comment of the form:

```python
# VULN-XX: CWE-nnn <short description>
```

The line **immediately following** such a marker (the "sink" line) is the line
recorded in `reference.sarif`. Because `reference.sarif` is generated from these
markers by `gen_reference.py`, the ground-truth line numbers always match the
code exactly — edit the source, rerun the generator, done.

```bash
python3 gen_reference.py --src src --out reference.sarif
python3 gen_docs.py --reference reference.sarif --out VULNERABILITIES.md
```

## Building the submission archive

Most SAST tools want a single `.zip`. Build it from the parent directory so the
archive keeps the `vulnerable-python-app/` top-level folder, excluding VCS/IDE
noise and Python caches:

```bash
# From the directory that CONTAINS vulnerable-python-app/
zip -r vulnerable-python-app.zip vulnerable-python-app \
  -x '*/__pycache__/*' -x '*.pyc' \
  -x '*/.git/*' -x '*/.idea/*' -x '*/.vscode/*' \
  -x '*/.venv/*' -x '*/venv/*' -x '*/.DS_Store'
```

If `zip` isn't installed, build the archive with pure Python instead:

```bash
# From the directory that CONTAINS vulnerable-python-app/
python3 - <<'PY'
import zipfile, os
root = "vulnerable-python-app"
skip_dirs = {"__pycache__", ".git", ".idea", ".vscode", ".venv", "venv"}
skip_ext = {".pyc", ".pyo", ".zip"}
with zipfile.ZipFile("vulnerable-python-app.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for f in sorted(files):
            if os.path.splitext(f)[1] in skip_ext:
                continue
            z.write(os.path.join(dp, f))
PY
```

Verify before submitting:

```bash
python3 -c "import zipfile; [print(n) for n in zipfile.ZipFile('vulnerable-python-app.zip').namelist()]"
```

## Usage

```bash
python3 sast_checker.py --reference reference.sarif --actual tool_output.sarif
```

See `sast_checker.py --help` for matching options (line tolerance, matching by
rule/CWE vs. by location, etc.).

### Handling tools that don't emit CWE ids

Some SAST tools produce SARIF where the `ruleId` is a human-readable name
("SQL Injection", "OS Commanding", ...) with no CWE id. The checker handles this
via a built-in `RULE_NAME_TO_CWE` table and by reading `rule.messageStrings[id]`.
If your tool uses names the table doesn't know, add them there.

### Matching strategies

- `--match location` (default): match on same file + line within `--tolerance`
  (default 3). Tools often report a nearby line rather than the exact sink, so a
  small tolerance is expected. Add `--require-cwe` to also demand a CWE match.
- `--match cwe`: match on CWE class within the same file (use `--cwe-any-file`
  to ignore file). Coarser; useful when line numbers differ a lot.

### Notes on "extra" findings

Extra (unmatched) tool findings are bucketed into false positives, duplicates,
dependency/SCA findings, and non-source findings. Review the EXTRA list before
treating them all as false positives.

## Self-test

Sanity check that reference matches itself perfectly:

```bash
python3 sast_checker.py -r reference.sarif -a reference.sarif
# => matched=60/60 recall=100.00% precision=100.00% f1=100.00%
```

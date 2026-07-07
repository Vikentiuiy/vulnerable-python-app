"""Authentication, authorization and API vulnerabilities.

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.
"""

import base64
import hmac
import logging

logger = logging.getLogger("vulnapp")


def missing_authentication(request, db):
    user_id = request.args.get("user_id")
    # VULN-38: CWE-306 Missing authentication for critical function (delete)
    db.execute("DELETE FROM users WHERE id=?", (user_id,))


def idor_no_owner_check(request, db):
    doc_id = request.args.get("doc_id")
    # VULN-39: CWE-639 IDOR / authorization bypass - no owner check
    return db.execute("SELECT body FROM docs WHERE id=?", (doc_id,)).fetchone()


def improper_privilege_management(request):
    # VULN-40: CWE-269 Improper privilege management - role from client input
    role = request.args.get("role", "user")
    return {"admin": role == "admin"}


def plaintext_password_storage(db, username: str, password: str):
    # VULN-41: CWE-256 Plaintext storage of password
    db.execute("INSERT INTO users(name, password) VALUES(?,?)", (username, password))


def base64_not_encryption(secret: str):
    # VULN-42: CWE-326 Base64 mistaken for encryption of sensitive data
    return base64.b64encode(secret.encode()).decode()


def improper_authentication_client_id(request):
    # VULN-43: CWE-287 Improper authentication - trusting client-supplied id
    return {"logged_in_as": request.headers.get("X-User-Id")}


def weak_password_requirement(password: str):
    # VULN-44: CWE-521 Weak password requirement - accepts empty/short
    return len(password) >= 0


def timing_unsafe_compare(provided: str, expected: str):
    # VULN-45: CWE-208 Non-constant-time comparison of secret
    return provided == expected


def jwt_no_verify(token: str):
    import jwt
    # VULN-46: CWE-347 JWT signature not verified
    return jwt.decode(token, options={"verify_signature": False})


def hardcoded_jwt_secret(payload: dict):
    import jwt
    # VULN-47: CWE-798 Hard-coded / weak JWT signing secret
    return jwt.encode(payload, "secret", algorithm="HS256")


def missing_rate_limiting(request, db):
    # VULN-48: CWE-307 Improper restriction of excessive auth attempts
    return db.execute("SELECT 1 FROM users WHERE name=? AND password=?",
                      (request.form["u"], request.form["p"])).fetchone()


def verbose_error_exposure(request):
    try:
        return 1 / int(request.args.get("n"))
    except Exception as e:
        import traceback
        # VULN-49: CWE-209 Sensitive information exposure via stack trace
        return traceback.format_exc()

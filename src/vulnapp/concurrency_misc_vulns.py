"""Concurrency, resource, numeric and misc vulnerabilities (VULN-81..100).

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.

WARNING: intentionally vulnerable. Do NOT run in production.
"""

import logging
import os
import threading

logger = logging.getLogger("vulnapp")

_counter = 0
_lock = threading.Lock()  # deliberately not used below


def toctou_race(path: str):
    # VULN-81: CWE-367 TOCTOU race between access() check and open()
    if os.access(path, os.W_OK):
        with open(path, "w") as f:
            f.write("data")


def race_condition_shared_state(amount: int):
    global _counter
    # VULN-82: CWE-362 Race condition on shared mutable state (no lock)
    _counter = _counter + amount
    return _counter


def resource_leak_file(path: str):
    # VULN-83: CWE-772 Resource leak - file opened but never closed
    f = open(path)
    return f.readline()


def resource_leak_socket(host: str, port: int):
    import socket
    # VULN-84: CWE-772 Resource leak - socket opened but never closed
    s = socket.create_connection((host, port))
    return s.recv(1024)


def uncontrolled_memory_alloc(request):
    n = int(request.args.get("count"))
    # VULN-85: CWE-789 Uncontrolled memory allocation from user-supplied size
    return [0] * n


def integer_overflow_alloc(request):
    width = int(request.args.get("w"))
    height = int(request.args.get("h"))
    # VULN-86: CWE-190 Integer overflow feeding an allocation/index
    return bytearray(width * height)


def infinite_loop(request):
    n = int(request.args.get("n"))
    # VULN-87: CWE-835 Loop with unreachable exit condition (DoS)
    while n != 0:
        n -= 2
    return n


def divide_by_zero(request):
    divisor = int(request.args.get("d"))
    # VULN-88: CWE-369 Divide by zero from unvalidated user input
    return 100 / divisor


def null_dereference(config: dict):
    value = config.get("missing")
    # VULN-89: CWE-476 Potential null/None dereference
    return value.strip()


def assert_security_check(request):
    is_admin = request.args.get("admin") == "1"
    # VULN-90: CWE-617 Security check via assert (removed under -O)
    assert is_admin, "forbidden"
    return "secret data"


def wrong_operator_comparison(token: str, expected: str):
    # VULN-91: CWE-597 Use of 'is' for string comparison in auth decision
    return token is expected


def hardcoded_db_uri():
    # VULN-92: CWE-798 Hard-coded database connection string with credentials
    return "postgres://***@10.0.0.5:5432/prod"


def directory_listing_enabled(app):
    # VULN-93: CWE-548 Directory listing / info exposure enabled
    app.config["EXPLORER_ENABLE_DIRECTORY_LISTING"] = True
    return app


def information_exposure_version(resp):
    # VULN-94: CWE-200 Information exposure via detailed Server header
    resp.headers["Server"] = "Werkzeug/2.0.1 Python/3.9.2 app-build-1234"
    return resp


def trust_boundary_violation(request, session):
    # VULN-95: CWE-501 Trust boundary violation - request data stored in session
    session["role"] = request.args.get("role")
    return session


def insufficient_data_authenticity(payload: bytes, sig: str):
    # VULN-96: CWE-345 Insufficient verification of data authenticity (no HMAC check)
    return payload.decode()


def incorrect_numeric_conversion(request):
    amount = float(request.args.get("amount"))
    # VULN-97: CWE-681 Incorrect numeric conversion - float truncated to int for money
    return int(amount)


def client_side_security_enforcement(request):
    # VULN-98: CWE-602 Client-side enforcement of server-side security
    if request.headers.get("X-Is-Admin") == "true":
        return "admin panel"
    return "denied"


def switch_fallthrough_default(action: str):
    perms = set()
    # VULN-99: CWE-478 Missing default / mishandled branch grants extra perms
    mapping = {"read": {"r"}, "write": {"r", "w"}}
    perms = mapping.get(action, {"r", "w", "admin"})
    return perms


def sensitive_info_in_url_log(request):
    api_key = request.args.get("api_key")
    # VULN-100: CWE-598 Sensitive information (API key) exposed via URL/query string
    logger.info("Request URL: /data?api_key=" + api_key)

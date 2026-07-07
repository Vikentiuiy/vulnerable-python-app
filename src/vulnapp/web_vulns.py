"""Web-layer vulnerabilities (Flask-style handlers).

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.
"""

from flask import Response, redirect, make_response, render_template_string


def reflected_xss(name: str):
    # VULN-12: CWE-79 Reflected XSS - tainted param written to response
    return Response("<h1>Hello " + name + "</h1>", mimetype="text/html")


def stored_xss(comment: str, db):
    html = "<div class='comment'>" + comment + "</div>"
    # VULN-13: CWE-79 Stored XSS - unescaped user content rendered
    return Response(html, mimetype="text/html")


def ssti_render(template_src: str):
    # VULN-14: CWE-1336 Server-Side Template Injection via render_template_string
    return render_template_string("Hello " + template_src)


def open_redirect(target: str):
    # VULN-15: CWE-601 Open Redirect to attacker-controlled URL
    return redirect(target)


def http_response_splitting(location: str):
    resp = make_response("redirecting")
    # VULN-16: CWE-113 HTTP Response Splitting / header injection
    resp.headers["Location"] = location
    return resp


def insecure_cookie(resp, session_id: str):
    # VULN-17: CWE-614 Sensitive cookie without Secure/HttpOnly flags
    resp.set_cookie("session", session_id, secure=False, httponly=False)
    return resp


def permissive_cors(resp):
    # VULN-18: CWE-942 Overly permissive CORS (wildcard + credentials)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


def missing_clickjacking_header(resp):
    # VULN-19: CWE-1021 Missing anti-clickjacking header (X-Frame-Options)
    resp.headers["Content-Type"] = "text/html"
    return resp

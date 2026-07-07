"""Advanced injection & web vulnerabilities (VULN-61..80).

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.

WARNING: intentionally vulnerable. Do NOT run in production.
"""

import os
import re
import sqlite3
import subprocess

from flask import Response, make_response, render_template_string


def second_order_sqli(conn: sqlite3.Connection, stored_name: str):
    cur = conn.cursor()
    # VULN-61: CWE-89 Second-order SQL injection from previously stored value
    cur.execute("SELECT * FROM orders WHERE customer = '" + stored_name + "'")
    return cur.fetchall()


def blind_sqli_like(conn: sqlite3.Connection, term: str):
    cur = conn.cursor()
    # VULN-62: CWE-89 SQL injection in LIKE clause
    cur.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")
    return cur.fetchall()


def argument_injection(user_file: str):
    # VULN-63: CWE-88 Argument injection into git via unsanitized input
    return subprocess.check_output(["git", "log", user_file])


def expression_lang_injection(template, user_expr: str):
    # VULN-64: CWE-917 Expression language / Jinja expression injection
    return render_template_string("{{ " + user_expr + " }}")


def xpath_injection(tree, user: str):
    # VULN-65: CWE-643 XPath injection via concatenated expression
    return tree.xpath("//users/user[name='" + user + "']")


def header_injection_crlf(resp, filename: str):
    # VULN-66: CWE-93 CRLF / header injection via Content-Disposition
    resp.headers["Content-Disposition"] = "attachment; filename=" + filename
    return resp


def reflected_xss_dom(fragment: str):
    body = "<script>var d='" + fragment + "';</script>"
    # VULN-67: CWE-79 DOM-context XSS - input injected into inline script
    return Response(body, mimetype="text/html")


def unsafe_content_type_sniffing(data: str):
    resp = make_response(data)
    # VULN-68: CWE-116 Missing output encoding / no nosniff protection
    resp.headers["Content-Type"] = "text/html"
    return resp


def format_string_injection(user_fmt: str, value):
    # VULN-69: CWE-134 Uncontrolled format string
    return user_fmt % value


def prototype_style_mass_assign(model, request):
    # VULN-70: CWE-915 Mass assignment - bind all request params to object
    for k, v in request.form.items():
        setattr(model, k, v)
    return model


def open_redirect_header(resp, next_url: str):
    # VULN-71: CWE-601 Open redirect via Refresh header
    resp.headers["Refresh"] = "0; url=" + next_url
    return resp


def ssrf_redirect_follow(url: str):
    import requests
    # VULN-72: CWE-918 SSRF - user URL fetched, redirects followed
    return requests.get(url, allow_redirects=True).text


def xml_bomb_billion_laughs(xml_bytes: bytes):
    import xml.sax
    parser = xml.sax.make_parser()
    # VULN-73: CWE-776 XML entity expansion (billion laughs) not disabled
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    return parser


def insecure_cookie_no_samesite(resp, token: str):
    # VULN-74: CWE-1275 Cookie without SameSite attribute (CSRF exposure)
    resp.set_cookie("auth", token, samesite=None)
    return resp


def csrf_no_token(request, db):
    # VULN-75: CWE-352 State-changing POST without CSRF token verification
    db.execute("UPDATE settings SET email=?", (request.form["email"],))


def host_header_injection(request):
    host = request.headers.get("Host")
    # VULN-76: CWE-644 Host header used to build password-reset link
    return "https://" + host + "/reset?token=abc"


def open_redirect_meta(url: str):
    body = "<meta http-equiv='refresh' content='0;url=" + url + "'>"
    # VULN-77: CWE-601 Open redirect via attacker-controlled meta refresh
    return Response(body, mimetype="text/html")


def command_injection_env(user_val: str):
    os.environ["USER_INPUT"] = user_val
    # VULN-78: CWE-78 OS command injection via shell expansion of env var
    return subprocess.check_output("echo $USER_INPUT", shell=True)


def template_injection_mako(tmpl_src: str):
    from mako.template import Template
    # VULN-79: CWE-1336 SSTI via Mako template built from user input
    return Template(tmpl_src).render()


def regex_dos_catastrophic(user_input: str):
    # VULN-80: CWE-1333 ReDoS - catastrophic backtracking on user input
    return re.match(r"^(a+)+$", user_input)

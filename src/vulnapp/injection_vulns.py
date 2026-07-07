"""Injection-family vulnerabilities.

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.

WARNING: intentionally vulnerable. Do NOT run in production.
"""

import os
import re
import sqlite3
import subprocess


def sql_injection_concat(conn: sqlite3.Connection, user_id: str):
    cur = conn.cursor()
    # VULN-01: CWE-89 SQL Injection via string concatenation
    cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return cur.fetchall()


def sql_injection_format(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    q = "SELECT * FROM accounts WHERE name = '%s'" % name
    # VULN-02: CWE-89 SQL Injection via %-format-built query
    cur.execute(q)
    return cur.fetchall()


def sql_injection_fstring(conn: sqlite3.Connection, role: str, uid: str):
    cur = conn.cursor()
    # VULN-03: CWE-89 SQL Injection via f-string in UPDATE
    cur.execute(f"UPDATE users SET role='{role}' WHERE id={uid}")
    return cur.rowcount


def os_command_injection_shell(host: str):
    # VULN-04: CWE-78 OS Command Injection via os.system
    os.system("ping -c 1 " + host)


def os_command_injection_popen(filename: str):
    # VULN-05: CWE-78 OS Command Injection via subprocess shell=True
    return subprocess.check_output("cat " + filename, shell=True)


def os_command_injection_popen_list(user_arg: str):
    cmd = "ls " + user_arg
    # VULN-06: CWE-78 OS Command Injection via os.popen
    return os.popen(cmd).read()


def code_injection_eval(expr: str):
    # VULN-07: CWE-95 Code injection via eval() of user input
    return eval(expr)


def code_injection_exec(src: str):
    # VULN-08: CWE-95 Code injection via exec() of user input
    exec(src)


def ldap_injection(conn, username: str):
    # VULN-09: CWE-90 LDAP Injection via unsanitized filter
    return conn.search_s("ou=users,dc=example,dc=com", 2, "(uid=" + username + ")")


def nosql_injection(collection, username: str):
    # VULN-10: CWE-943 NoSQL injection via $where with user input
    return collection.find({"$where": "this.name == '" + username + "'"})


def regex_injection_redos(user_pattern: str, text: str):
    # VULN-11: CWE-1333 ReDoS - user-controlled regex pattern
    return re.match(user_pattern, text)

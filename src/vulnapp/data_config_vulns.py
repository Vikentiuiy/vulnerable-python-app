"""Data-handling, XML, logging and configuration vulnerabilities.

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.
"""

import logging
import ssl
import xml.etree.ElementTree as ET

import yaml

logger = logging.getLogger("vulnapp")


def xxe_parse(xml_bytes: bytes):
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    # VULN-50: CWE-611 XXE - external entities resolved on untrusted XML
    return etree.fromstring(xml_bytes, parser)


def unsafe_yaml_load(data: str):
    # VULN-51: CWE-502 Unsafe YAML deserialization (yaml.load without SafeLoader)
    return yaml.load(data, Loader=yaml.Loader)


def unsafe_reflection(class_name: str):
    import importlib
    # VULN-52: CWE-470 Unsafe reflection - importing module from untrusted name
    return importlib.import_module(class_name)


def log_injection(request):
    username = request.args.get("username")
    # VULN-53: CWE-117 Log injection - unsanitized input written to log
    logger.info("Login attempt for user: " + username)


def sensitive_data_in_logs(card_number: str, cvv: str):
    # VULN-54: CWE-532 Sensitive data (PAN/CVV) written to logs
    logger.info("Processing card %s cvv %s", card_number, cvv)


def disabled_cert_validation(url: str):
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # VULN-55: CWE-295 TLS certificate validation disabled
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx)


def insecure_ssl_context():
    # VULN-56: CWE-327 Insecure/obsolete TLS protocol (SSLv23)
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def debug_mode_enabled(app):
    # VULN-57: CWE-489 Debug/development feature left active in production
    app.run(host="0.0.0.0", debug=True)


def cleartext_storage(config: dict, secret: str):
    # VULN-58: CWE-312 Cleartext storage of sensitive information
    open("/etc/app/creds.txt", "w").write(secret)


def improper_input_validation(request):
    size = request.args.get("size")
    # VULN-59: CWE-20 Improper input validation - value used unchecked
    return bytearray(int(size))


def unrestricted_file_upload(request):
    f = request.files["file"]
    # VULN-60: CWE-434 Unrestricted file upload - no type/extension check
    f.save("/var/www/uploads/" + f.filename)

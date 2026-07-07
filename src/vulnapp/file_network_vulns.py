"""File and network vulnerabilities.

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.
"""

import os
import pickle
import tarfile
import tempfile
import urllib.request


def path_traversal_read(filename: str):
    base = "/var/www/uploads/"
    # VULN-20: CWE-22 Path Traversal - tainted filename joined to base
    with open(base + filename) as f:
        return f.read()


def path_traversal_write(filename: str, data: str):
    # VULN-21: CWE-22 Path Traversal on write allows arbitrary file overwrite
    with open(os.path.join("/var/www/uploads/", filename), "w") as f:
        f.write(data)


def ssrf_request(url: str):
    # VULN-22: CWE-918 SSRF - request to user-controlled URL
    return urllib.request.urlopen(url).read()


def zip_slip(tar_path: str, dest: str):
    tf = tarfile.open(tar_path)
    # VULN-23: CWE-22 Tar Slip - members extracted without path validation
    tf.extractall(dest)
    tf.close()


def insecure_temp_file():
    # VULN-24: CWE-377 Insecure temporary file creation (predictable name)
    path = "/tmp/app_" + str(os.getpid()) + ".tmp"
    with open(path, "w") as f:
        f.write("data")
    return path


def overly_permissive_permissions(path: str):
    # VULN-25: CWE-732 Overly permissive file permissions (world-writable)
    os.chmod(path, 0o777)


def insecure_deserialization_pickle(data: bytes):
    # VULN-26: CWE-502 Insecure deserialization of untrusted data (pickle)
    return pickle.loads(data)

"""Crypto and secret-management vulnerabilities.

Every planted issue is tagged with a `# VULN-XX:` marker; the sink is the
line immediately following the marker.
"""

import hashlib
import random

# VULN-27: CWE-798 Hardcoded credentials (password)
DB_PASSWORD = "SuperSecret123!"
# VULN-28: CWE-798 Hardcoded cryptographic key
AES_KEY = b"0123456789abcdef"
# VULN-29: CWE-259 Hardcoded API token
API_TOKEN = "sk_live_51H8xYzABCDEF0123456789"


def weak_hash_md5(password: str):
    # VULN-30: CWE-327 Weak hashing algorithm MD5
    return hashlib.md5(password.encode()).hexdigest()


def weak_hash_sha1(data: str):
    # VULN-31: CWE-327 Weak hashing algorithm SHA-1
    return hashlib.sha1(data.encode()).hexdigest()


def weak_cipher_des(data: bytes):
    from Crypto.Cipher import DES
    # VULN-32: CWE-327 Weak/broken cipher DES
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return cipher.encrypt(data)


def ecb_mode_cipher(data: bytes):
    from Crypto.Cipher import AES
    # VULN-33: CWE-327 Insecure ECB block cipher mode
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(data)


def static_iv_cbc(data: bytes):
    from Crypto.Cipher import AES
    iv = b"\x00" * 16
    # VULN-34: CWE-329 Static/zero IV used for CBC encryption
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return cipher.encrypt(data)


def insecure_randomness_token():
    # VULN-35: CWE-330 Insecure randomness for security token
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def predictable_seed():
    # VULN-36: CWE-337 Predictable seed for PRNG
    random.seed(1234)
    return random.random()


def password_hash_no_salt(password: str):
    # VULN-37: CWE-759 Password hashed without a salt
    return hashlib.sha256(password.encode()).hexdigest()

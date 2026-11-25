#!/usr/bin/env python3
"""Generate legacy password hash vectors, independently of the Go code.

Usage: python3 gen_legacy_vectors.py > legacy_vectors.json

bcrypt hashes come from Apache htpasswd (-B), which writes the $2y$ prefix.
$2a$, $2b$ and $2y$ name the same algorithm for these inputs, so the $2a$
and $2b$ vectors reuse the htpasswd output with the prefix swapped.

The scrypt vectors use the Werkzeug format (scrypt:N:r:p$salt$hex) and the
PBKDF2 vectors use the Django format (pbkdf2_sha256$iter$salt$base64). Both
are computed with Python's hashlib, following werkzeug.security and
django.contrib.auth.hashers: the password and salt are UTF-8 bytes, the
scrypt key is 64 bytes and the PBKDF2 key is 32 bytes.
"""
import base64
import hashlib
import json
import subprocess

PASSWORDS = ["password", "correct horse battery staple", "café"]


def htpasswd(password: str, cost: int) -> str:
    out = subprocess.run(
        ["htpasswd", "-niB", "-C", str(cost), "user"],
        input=password.encode(),
        capture_output=True,
        check=True,
    ).stdout.decode()
    return out.strip().split(":", 1)[1]


def werkzeug_scrypt(password: str, salt: str, n: int, r: int, p: int) -> str:
    key = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=n, r=r, p=p, maxmem=132 * n * r * p
    )
    return f"scrypt:{n}:{r}:{p}${salt}${key.hex()}"


def django_pbkdf2(password: str, salt: str, iterations: int) -> str:
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(key).decode()}"


def main():
    vectors = []
    for i, pw in enumerate(PASSWORDS):
        y = htpasswd(pw, 5)
        for prefix in ("$2y$", "$2a$", "$2b$"):
            vectors.append({"source": "htpasswd -B", "password": pw, "hash": prefix + y[4:]})
        vectors.append({
            "source": "hashlib.scrypt, Werkzeug format",
            "password": pw,
            "hash": werkzeug_scrypt(pw, f"salt{i}Werkzeug{i}", 1024, 8, 1),
        })
        vectors.append({
            "source": "hashlib.pbkdf2_hmac, Django format",
            "password": pw,
            "hash": django_pbkdf2(pw, f"salt{i}Django{i}", 1000),
        })
    # Library defaults: htpasswd cost 10 (bcrypt), Werkzeug 3 scrypt
    # (N=2^15, r=8, p=1, 16-character salt), Django 5.2 PBKDF2 (1,000,000
    # iterations, 22-character salt).
    vectors.append({"source": "htpasswd -B", "password": "password", "hash": htpasswd("password", 10)})
    vectors.append({
        "source": "hashlib.scrypt, Werkzeug format",
        "password": "password",
        "hash": werkzeug_scrypt("password", "s4ltS4ltS4ltS4lt", 32768, 8, 1),
    })
    vectors.append({
        "source": "hashlib.pbkdf2_hmac, Django format",
        "password": "password",
        "hash": django_pbkdf2("password", "s4ltS4ltS4ltS4ltS4ltS4", 1000000),
    })
    print(json.dumps(vectors, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()

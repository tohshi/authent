#!/usr/bin/env python3
"""Generate an x5c certificate chain test vector with OpenSSL.

Usage: python3 gen_openssl_x5c.py > openssl_x5c.json

A root CA, an intermediate CA and an ES256 leaf are created with the openssl
CLI. The output holds the root certificate, the leaf's public JWK with the
x5c chain (leaf, intermediate) and a token signed with the leaf key, so the
x5c parsing and chain verification are checked against certificates that
Go's crypto/x509 did not produce.
"""
import base64
import json
import os
import subprocess
import tempfile


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


def der_len(buf, i):
    n = buf[i]
    i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7F
    return int.from_bytes(buf[i:i + k], "big"), i + k


def ecdsa_der_to_raw(der: bytes, size: int) -> bytes:
    assert der[0] == 0x30
    _, i = der_len(der, 1)
    out = b""
    for _ in range(2):
        assert der[i] == 0x02
        n, i = der_len(der, i + 1)
        out += int.from_bytes(der[i:i + n], "big").to_bytes(size, "big")
        i += n
    return out


def main():
    with tempfile.TemporaryDirectory() as d:
        def path(name):
            return os.path.join(d, name)

        def key(name):
            run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path(name + ".key"))

        def ext(name, text):
            with open(path(name + ".ext"), "w") as f:
                f.write(text)

        def issue(name, cn, issuer, serial, extensions):
            key(name)
            run("openssl", "req", "-new", "-key", path(name + ".key"), "-subj", "/CN=" + cn, "-out", path(name + ".csr"))
            ext(name, extensions)
            run("openssl", "x509", "-req", "-in", path(name + ".csr"), "-CA", path(issuer + ".crt"),
                "-CAkey", path(issuer + ".key"), "-set_serial", serial, "-days", "3650",
                "-extfile", path(name + ".ext"), "-out", path(name + ".crt"))

        def der(name):
            return run("openssl", "x509", "-in", path(name + ".crt"), "-outform", "DER")

        key("root")
        run("openssl", "req", "-x509", "-new", "-key", path("root.key"), "-subj", "/CN=authent test root",
            "-days", "3650", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", path("root.crt"))
        issue("inter", "authent test intermediate", "root", "2",
              "basicConstraints=critical,CA:TRUE,pathlen:0\n"
              "keyUsage=critical,keyCertSign\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        issue("leaf", "authent test signer", "inter", "3",
              "basicConstraints=critical,CA:FALSE\n"
              "keyUsage=critical,digitalSignature\n"
              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")

        spki = run("openssl", "pkey", "-in", path("leaf.key"), "-pubout", "-outform", "DER")
        point = spki[-65:]
        assert point[0] == 4
        jwk = {
            "kty": "EC", "crv": "P-256", "kid": "leaf",
            "x": b64u(point[1:33]), "y": b64u(point[33:]),
            "x5c": [base64.b64encode(der("leaf")).decode(), base64.b64encode(der("inter")).decode()],
        }

        header = json.dumps({"alg": "ES256", "kid": "leaf"}, separators=(",", ":")).encode()
        payload = json.dumps(
            {"iss": "https://issuer.example", "sub": "alice", "aud": "api", "exp": 4102444800},
            separators=(",", ":"),
        ).encode()
        inp = (b64u(header) + "." + b64u(payload)).encode()
        sig = ecdsa_der_to_raw(run("openssl", "dgst", "-sha256", "-sign", path("leaf.key"), data=inp), 32)

        print(json.dumps({
            "root": base64.b64encode(der("root")).decode(),
            "jwk": jwk,
            "token": inp.decode() + "." + b64u(sig),
        }, indent=2))


if __name__ == "__main__":
    main()

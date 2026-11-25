#!/usr/bin/env python3
"""Generate JWS test vectors with OpenSSL, independently of the Go code.

Usage: python3 gen_openssl_vectors.py > openssl_vectors.json

Keys, signatures and the JWK encodings are produced with the openssl CLI and
the Python standard library only, so the vectors check our JWS framing,
base64url handling, ECDSA R||S encoding and JWK parsing against a separate
implementation.
"""
import base64
import json
import subprocess
import tempfile
import os


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
        v = int.from_bytes(der[i:i + n], "big")
        i += n
        out += v.to_bytes(size, "big")
    return out


def spki_tail(keyfile: str, n: int) -> bytes:
    der = run("openssl", "pkey", "-in", keyfile, "-pubout", "-outform", "DER")
    return der[-n:]


def rsa_jwk(keyfile):
    text = run("openssl", "rsa", "-in", keyfile, "-noout", "-modulus").decode()
    n = bytes.fromhex(text.strip().split("=", 1)[1])
    return {"kty": "RSA", "n": b64u(n), "e": b64u((65537).to_bytes(3, "big"))}


def main():
    payload = json.dumps(
        {"iss": "https://issuer.example", "sub": "alice", "aud": "api", "exp": 4102444800},
        separators=(",", ":"),
    ).encode()
    vectors = []
    with tempfile.TemporaryDirectory() as d:
        def key(name, *genargs):
            path = os.path.join(d, name + ".pem")
            run("openssl", "genpkey", *genargs, "-out", path)
            return path

        rsa = key("rsa", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
        ec = {
            "ES256": (key("p256", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"), "P-256", 32, "sha256"),
            "ES384": (key("p384", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"), "P-384", 48, "sha384"),
            "ES512": (key("p521", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"), "P-521", 66, "sha512"),
        }
        ed = key("ed", "-algorithm", "ED25519")

        def emit(alg, jwk, signer):
            h = json.dumps({"alg": alg, "kid": "k-" + alg, "typ": "JWT"}, separators=(",", ":")).encode()
            inp = (b64u(h) + "." + b64u(payload)).encode()
            sig = signer(inp)
            vectors.append({"alg": alg, "jwk": dict(jwk, kid="k-" + alg), "token": inp.decode() + "." + b64u(sig)})

        for alg, md in [("RS256", "sha256"), ("RS384", "sha384"), ("RS512", "sha512")]:
            emit(alg, rsa_jwk(rsa), lambda inp, md=md: run("openssl", "dgst", "-" + md, "-sign", rsa, data=inp))
        for alg, md in [("PS256", "sha256"), ("PS384", "sha384"), ("PS512", "sha512")]:
            emit(alg, rsa_jwk(rsa), lambda inp, md=md: run(
                "openssl", "dgst", "-" + md, "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:digest", "-sign", rsa, data=inp))
        for alg, (path, crv, size, md) in ec.items():
            point = spki_tail(path, 1 + 2 * size)
            assert point[0] == 4
            jwk = {"kty": "EC", "crv": crv, "x": b64u(point[1:1 + size]), "y": b64u(point[1 + size:])}
            emit(alg, jwk, lambda inp, path=path, md=md, size=size: ecdsa_der_to_raw(
                run("openssl", "dgst", "-" + md, "-sign", path, data=inp), size))
        def ed_sign(inp):
            # Ed25519 signs the whole message, so it needs a seekable file.
            msg = os.path.join(d, "msg")
            with open(msg, "wb") as f:
                f.write(inp)
            return run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", ed, "-in", msg)

        emit("EdDSA", {"kty": "OKP", "crv": "Ed25519", "x": b64u(spki_tail(ed, 32))}, ed_sign)

    print(json.dumps({"payload": payload.decode(), "vectors": vectors}, indent=2))


if __name__ == "__main__":
    main()

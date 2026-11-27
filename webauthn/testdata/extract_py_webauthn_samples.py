#!/usr/bin/env python3
"""Extract real attestation samples from the py_webauthn test suite.

Usage:
    curl -sSL https://codeload.github.com/duo-labs/py_webauthn/tar.gz/<commit> | tar -xz
    python3 -I extract_py_webauthn_samples.py py_webauthn-<commit> <commit> > py_webauthn_samples.json

The registration responses were captured from real authenticators (TPMs
of Windows laptops, Android phones and an iPhone) by the py_webauthn
maintainers. The test files are parsed with ast and never executed. Some
responses use padded or standard base64; their binary members are
re-encoded as unpadded base64url, the encoding of WebAuthn L3 JSON, with
the bytes unchanged. The trust roots come from
webauthn/helpers/known_root_certs.py.
"""
import ast
import base64
import json
import sys

FILES = {
    "tpm": "tests/test_verify_registration_response_tpm.py",
    "android-key": "tests/test_verify_registration_response_android_key.py",
    "apple": "tests/test_verify_registration_response_apple.py",
}


def const(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):  # "...".encode("utf-8")
        return const(node.func.value)
    if isinstance(node, ast.Call) and node.args:  # base64url_to_bytes("...")
        return const(node.args[0])
    return None


def b64url(s):
    raw = base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4), validate=True)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def samples(path, fmt):
    for fn in ast.parse(open(path, encoding="utf-8").read()).body[-1].body:
        if not isinstance(fn, ast.FunctionDef) or not fn.name.startswith("test_"):
            continue
        s = {"format": fmt, "name": fn.name}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name, value = node.targets[0].id, const(node.value)
                if name in ("credential", "challenge", "rp_id", "expected_origin") and isinstance(value, str):
                    s[name] = value
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "set_time":
                args = [a.value for a in node.args[0].args]
                s["time"] = "%04d-%02d-%02dT%02d:%02d:%02dZ" % tuple(args + [0] * (6 - len(args)))
        cred = json.loads(s["credential"])
        cred["id"] = cred["rawId"] = b64url(cred["rawId"])
        for k in ("clientDataJSON", "attestationObject"):
            cred["response"][k] = b64url(cred["response"][k])
        s["credential"] = json.dumps(cred, separators=(",", ":"))
        yield s


def roots(path):
    out = {}
    for node in ast.parse(open(path, encoding="utf-8").read()).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            v = const(node.value)
            if isinstance(v, bytes):
                v = v.decode()
            if isinstance(v, str) and "BEGIN CERTIFICATE" in v:
                out[node.targets[0].id] = v
    return out


def main():
    root, commit = sys.argv[1], sys.argv[2]
    out = {
        "source": "https://github.com/duo-labs/py_webauthn/tree/" + commit,
        "license": "BSD-3-Clause, Copyright (c) Duo Security, Inc.",
        "samples": [s for fmt, f in FILES.items() for s in samples(root + "/" + f, fmt)],
        "roots": roots(root + "/webauthn/helpers/known_root_certs.py"),
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

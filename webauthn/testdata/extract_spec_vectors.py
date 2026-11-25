#!/usr/bin/env python3
"""Extract the WebAuthn Level 3 test vectors (§16) into JSON.

Usage:
    curl -sSL -o webauthn-3.html https://www.w3.org/TR/webauthn-3/
    python3 extract_spec_vectors.py webauthn-3.html > spec_vectors.json

The vectors are produced by the specification editors independently of
this package. Only the values a relying party needs are kept: the
challenges, clientDataJSON, attestationObject, authenticatorData,
signature, credential ID and the attestation trust root certificate.
"""
import html
import json
import re
import sys

KEYS = {"challenge", "credential_id", "clientDataJSON", "attestationObject",
        "authenticatorData", "signature"}


def text_of(doc: str) -> str:
    start = doc.index('id="sctn-test-vectors"')
    chunk = doc[start:doc.index('id="sctn-acknowledgements"')]
    chunk = re.sub(r"<(br|/p|/pre|/h\d|/li|/dt|/dd|/div)[^>]*>", "\n", chunk)
    chunk = re.sub(r"<[^>]+>", "", chunk)
    return html.unescape(chunk)


def main() -> None:
    text = text_of(open(sys.argv[1], encoding="utf-8").read())
    out = {"source": "https://www.w3.org/TR/webauthn-3/#sctn-test-vectors", "vectors": []}
    cur = None
    part = None
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^16\.(\d+)\. (.+)$", line)
        if m and m.group(2).startswith("Test Vectors for WebAuthn Extensions"):
            break
        if m:
            cur = {"section": "16." + m.group(1), "title": m.group(2),
                   "registration": {}, "authentication": {}}
            out["vectors"].append(cur)
            part = None
            continue
        if line in ("Registration:", "Authentication:"):
            part = line[:-1].lower()
            continue
        m = re.match(r"^(\w+) = h'([0-9a-f]*)'", line)
        if not m:
            continue
        name, value = m.groups()
        if name == "attestation_ca_cert":
            out["attestation_ca_cert"] = value
        elif cur is not None and part is not None and name in KEYS:
            cur[part][name] = value
    out["vectors"] = [v for v in out["vectors"] if v["registration"]]
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

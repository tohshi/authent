# Test vectors

[← authent README](../README.md)

`jwt/testdata/gen_openssl_vectors.py` generates
`jwt/testdata/openssl_vectors.json`, and
`jwt/testdata/gen_openssl_x5c.py` generates the certificate chain in
`jwt/testdata/openssl_x5c.json` with OpenSSL.

`webauthn/testdata/extract_spec_vectors.py` extracts
`webauthn/testdata/spec_vectors.json` from the WebAuthn Level 3 test vectors.
`webauthn/testdata/extract_py_webauthn_samples.py` extracts
`webauthn/testdata/py_webauthn_samples.json`, registrations captured from real
TPMs, Android phones and an iPhone, from the
[py_webauthn](https://github.com/duo-labs/py_webauthn) test suite.

The TOTP tests use the RFC 4226 and RFC 6238 vectors. These vectors come from
sources independent of this library.

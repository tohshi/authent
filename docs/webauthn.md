# WebAuthn

[← authent README](../README.md)

```go
rp, _ := webauthn.New(webauthn.Config{
	RPID:    "example.com",
	RPName:  "Example",
	Origins: []string{"https://example.com"},
}, store) // store implements webauthn.CredentialStore

// Registration
handle, _ := webauthn.NewUserHandle() // once per user; store it with the user
opts, ch, _ := rp.BeginRegistration(webauthn.User{Subject: "u1", Handle: handle, Name: "alice"}, existing)
// send opts as JSON, keep ch server-side (e.g. JSON in a session value) ...
reg, err := rp.FinishRegistration(ctx, ch, responseJSON) // then save reg.Credential

// Login: second factor for a known user, or a passkey without a username
opts, ch, _ = rp.BeginLogin(userCreds) // or rp.BeginDiscoverableLogin()
login, err := rp.FinishLogin(ctx, ch, responseJSON) // login.Principal, login.Credential
```
In the browser, pass the options to
`PublicKeyCredential.parseCreationOptionsFromJSON` (or
`parseRequestOptionsFromJSON`) and send back `credential.toJSON()`.

`FinishRegistration` and `FinishLogin` check:
- the challenge (single ceremony type, expiry), the origin, and the RP ID
  hash
- that `crossOrigin` is false, or that `topOrigin` is in `TopOrigins`. A
  page in `TopOrigins` must also allow the iframe with the
  `publickey-credentials-create` and `publickey-credentials-get`
  permissions policies
- the user presence flag, and the user verification flag when
  `UserVerification` is `required`
- the credential algorithm against an allow-list, with the key type and
  curve bound to the algorithm (ES256/384/512, EdDSA, RS256, PS256)
- the attestation statement for the `none`, `packed`, `fido-u2f`, `tpm`,
  `android-key` and `apple` formats. Other formats, including
  `android-safetynet`, are rejected. Set `AttestationRoots` to require a
  certificate chain to known roots, such as a TPM vendor's root, Google's
  hardware attestation roots or the Apple WebAuthn root. TPM statements
  may be signed with RS1 (RSA with SHA-1), which RFC 8812 registers as
  deprecated, only for TPM attestation; credential keys never may. For `android-key`, the union of the
  software-enforced and TEE-enforced authorization lists is checked, so
  keys outside a TEE are accepted
- that the credential is not already registered, belongs to the expected
  user, and was in `allowCredentials`
- the signature counter, which must increase unless it is always 0, and
  that backup eligibility does not change

Origins are matched exactly, never derived from the request:
- `Origins` lists web origins within the RP ID and Android app origins,
  `android:apk-key-hash:` followed by the unpadded base64url SHA-256
  fingerprint of the signing certificate
  ([Credential Manager](https://developer.android.com/identity/passkeys/create-passkeys)).
  iOS apps report `https://` followed by the RP ID
  ([Apple](https://developer.apple.com/forums/thread/719003)), so they need
  no extra entry.
- `RelatedOrigins` lists web origins outside the RP ID for
  [related origin requests](https://www.w3.org/TR/webauthn-3/#sctn-related-origins).
  Serve the same list at `https://<RP ID>/.well-known/webauthn`.

To trust the authenticators listed in the FIDO Metadata Service, verify
its BLOB and set `Config.Metadata`:
```go
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(globalSignRootR3) // https://secure.globalsign.com/cacert/root-r3.crt
md, err := webauthn.FetchMetadata(ctx, http.DefaultClient, webauthn.MDS3URL, roots)
rp, _ := webauthn.New(webauthn.Config{ /* ... */ Attestation: webauthn.ConveyanceDirect, Metadata: md}, store)
```
- `FetchMetadata` downloads the BLOB and the CRLs that its signing chain
  names, with the caller's client. `ParseMetadata` verifies BLOB bytes the
  caller already has; pass the CRLs with `WithCRLs`. As MDS3 requires, a
  BLOB is rejected unless a current CRL covers every certificate of its
  chain except the root, and it is rejected if any current CRL revokes
  one. The BLOB must come over https, also after the client's redirects,
  so that a network attacker cannot replay an older signed BLOB. CRLs may
  come over http because their signatures are checked.
- A listed authenticator's attestation must chain to the roots in its
  metadata statement. It is rejected when a status report says `REVOKED`,
  `USER_VERIFICATION_BYPASS`, `USER_KEY_REMOTE_COMPROMISE`,
  `USER_KEY_PHYSICAL_COMPROMISE` or `ATTESTATION_KEY_COMPROMISE`. A report
  that names a certificate applies only to chains that contain it. Any
  such report blocks the model for good. A later report, such as
  `FIDO_CERTIFIED_L2`, does not clear it. Authenticators that are not
  listed need a chain to `AttestationRoots`.
- The model is looked up by the AAGUID in the authenticator data. A model
  whose attestation certificate does not carry its AAGUID can claim the
  AAGUID of a sibling model under the same vendor root, and so escape its
  own status reports. This is inherent to MDS.
- Metadata is checked at registration, not at login. When you load a new
  BLOB, look up each stored `Credential.AAGUID` and decide what to do with
  credentials whose model is now reported as compromised.
- A BLOB past its `nextUpdate` is still accepted. Fetch a new BLOB before
  `NextUpdate()` and keep it only if its `Number()` is higher. To swap it while the RelyingParty runs, implement
  `MetadataSource` with an atomic pointer.

Ceremony options:
- `webauthn.WithConditionalCreate()` makes `BeginRegistration` start a
  registration for `navigator.credentials.create({mediation: "conditional",
  publicKey})`, which creates a passkey without a prompt, for example right
  after a password login. Only such registrations may lack the user
  presence flag. The `UserVerification` policy still applies.
- `webauthn.WithExtensions` requests the `credProps`, `prf`, `largeBlob`
  and `appid` extensions. The Begin methods reject inputs that the browser
  would reject, such as `credProps` at login. `Registration.Extensions` and
  `Login.Extensions` hold the client outputs of the requested extensions,
  which the browser reports without a signature, and every authenticator
  extension output from the signed authenticator data. With `appid`,
  `FinishLogin` expects the hash of the AppID instead of the RP ID only
  when the client reports that it used the AppID.
- The `Challenge` keeps the extension inputs, and Finish rejects outputs
  that they cannot produce. A `Challenge` serialized by an earlier version
  of this package with extensions (a list of names) no longer decodes,
  and its `appid` is dropped, so ceremonies in flight during an upgrade
  fail closed.

CBOR is decoded strictly: no tags, floats, indefinite lengths, duplicate
map keys or trailing bytes, with bounds on depth and length.

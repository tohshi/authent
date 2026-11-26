package authent_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/tohshi/authent"
	"github.com/tohshi/authent/jwt"
	"github.com/tohshi/authent/password"
	"github.com/tohshi/authent/rebac"
	"github.com/tohshi/authent/session"
)

type users map[string]password.Credential

func (u users) LookupCredential(_ context.Context, name string) (password.Credential, error) {
	if c, ok := u[name]; ok {
		return c, nil
	}
	return password.Credential{}, password.ErrUserNotFound
}

// Log in with a password, keep the login in a session, and authorize an
// action with ReBAC.
func Example() {
	ctx := context.Background()

	// authn: password -> Principal
	hasher, _ := password.NewHasher(password.DefaultParams)
	hash, _ := hasher.Hash("correct horse battery staple")
	login, _ := password.NewAuthenticator(users{"alice": {Subject: "u1", Hash: hash}}, hasher)
	p, err := login.Authenticate(ctx, "alice", "correct horse battery staple")
	if err != nil {
		panic(err)
	}

	// authn: Principal -> session token (to be stored in a cookie)
	sessions, _ := session.NewManager(session.NewMemoryStore())
	token, _, _ := sessions.Create(ctx, p)
	s, _ := sessions.Get(ctx, token)

	// authz: may the session's subject view the document?
	schema, _ := rebac.NewSchema(
		rebac.Type("user"),
		rebac.Type("doc",
			rebac.Relation("owner", rebac.Direct("user")),
			rebac.Relation("viewer", rebac.Union(rebac.Direct("user"), rebac.Computed("owner"))),
		),
	)
	engine, _ := rebac.NewEngine(schema, rebac.NewMemoryStore())
	_, _ = engine.Write(ctx, []rebac.Tuple{rebac.MustParseTuple("doc:readme#owner@user:u1")}, nil)

	ok, _ := engine.Check(ctx, rebac.Obj("doc", "readme"), "viewer", rebac.Sub("user", s.Principal().Subject))
	fmt.Println(ok)
	// Output: true
}

// Issue and verify an access token.
func Example_jwt() {
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner(jwt.ES256, key, jwt.WithKeyID("2026-01"))

	token, _ := signer.Sign(jwt.Claims{
		Issuer:    "https://auth.example",
		Subject:   "u1",
		Audience:  jwt.Audience{"api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
	})

	// Publish signer.VerificationKey() in a JWK Set; verifiers elsewhere
	// would use jwt.NewRemoteKeySet with its URL.
	verifier, _ := jwt.NewVerifier(jwt.NewStaticKeySet(signer.VerificationKey()),
		jwt.WithAlgorithms(jwt.ES256),
		jwt.WithIssuer("https://auth.example"),
		jwt.WithAudience("api"),
	)
	p, err := verifier.Authenticate(ctx, token)
	fmt.Println(p.Subject, p.Method, err)

	_, err = verifier.Authenticate(ctx, token+"x")
	fmt.Println(errors.Is(err, authent.ErrUnauthenticated))
	// Output:
	// u1 jwt <nil>
	// true
}

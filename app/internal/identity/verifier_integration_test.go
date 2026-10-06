package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestOIDCVerifierAgainstControlledIssuerAndJWKS(t *testing.T) {
	const tenant = "22345678-1234-4234-9234-123456789abc"
	const audience = "32345678-1234-4234-9234-123456789abc"
	const objectID = "42345678-1234-4234-9234-123456789abc"
	const oauthClient = "52345678-1234-4234-9234-123456789abc"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerURL := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuerURL, "jwks_uri": issuerURL + "/keys"})
		case "/keys":
			e := big.NewInt(int64(key.PublicKey.E)).Bytes()
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture-key",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(e),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuerURL = server.URL

	verifier, err := newVerifierForIssuer(tenant, audience, issuerURL, oauthClient)
	if err != nil {
		t.Fatal(err)
	}
	ctx := oidc.ClientContext(context.Background(), server.Client())
	now := time.Now()
	claims := map[string]any{
		"iss": issuerURL, "aud": audience, "tid": tenant, "oid": objectID,
		"ver": "2.0", "azp": oauthClient, "scp": "User.Read access_as_user", "exp": now.Add(time.Hour).Unix(),
		"email": "alex@example.test", "email_verified": true, "verified_primary_email": "alex@example.test",
	}
	validToken := signFixtureToken(t, key, claims)
	principal, err := verifier.Verify(ctx, validToken)
	if err != nil {
		t.Fatalf("valid signed token rejected: %v", err)
	}
	if principal.TenantID != tenant || principal.ObjectID != objectID {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if principal.VerifiedEmail != "alex@example.test" {
		t.Fatalf("verified email claim was not retained: %+v", principal)
	}
	unverifiedClaims := make(map[string]any, len(claims))
	for key, value := range claims {
		unverifiedClaims[key] = value
	}
	delete(unverifiedClaims, "verified_primary_email")
	unverified, err := verifier.Verify(ctx, signFixtureToken(t, key, unverifiedClaims))
	if err != nil || unverified.VerifiedEmail != "" {
		t.Fatalf("unverified email was accepted for mapping: principal=%+v err=%v", unverified, err)
	}

	for name, change := range map[string]func(map[string]any){
		"wrong audience": func(c map[string]any) { c["aud"] = "62345678-1234-4234-9234-123456789abc" },
		"wrong tenant":   func(c map[string]any) { c["tid"] = "62345678-1234-4234-9234-123456789abc" },
		"missing scope":  func(c map[string]any) { c["scp"] = "User.Read" },
		"app token":      func(c map[string]any) { c["idtyp"] = "app" },
		"unknown client": func(c map[string]any) { c["azp"] = "62345678-1234-4234-9234-123456789abc" },
		"expired token":  func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			badClaims := make(map[string]any, len(claims))
			for k, v := range claims {
				badClaims[k] = v
			}
			change(badClaims)
			if _, err := verifier.Verify(ctx, signFixtureToken(t, key, badClaims)); err == nil {
				t.Fatal("invalid token was accepted")
			}
		})
	}

	parts := strings.Split(validToken, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("bad signature"))
	if _, err := verifier.Verify(ctx, strings.Join(parts, ".")); err == nil {
		t.Fatal("invalid signature was accepted")
	}
}

func signFixtureToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "fixture-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

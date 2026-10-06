package identity

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var ErrMetadataUnavailable = errors.New("tenant identity metadata unavailable")

// These are the Microsoft first-party clients documented for Teams/Microsoft 365 SSO.
var authorizedClients = map[string]struct{}{
	"1fec8e78-bce4-4aaf-ab1b-5451cc387264": {}, // Teams desktop and mobile
	"5e3ce6c0-2b1f-4285-8d4b-75ee78787346": {}, // Teams web
	"4765445b-32c6-49b0-83e6-1d93765276ca": {}, // Microsoft 365 web
	"0ec893e0-5785-4de6-99da-4ed124e5296c": {}, // Microsoft 365 desktop
}

type Principal struct {
	TenantID      string `json:"tenantId"`
	ObjectID      string `json:"objectId"`
	VerifiedEmail string `json:"-"`
}

type Verifier struct {
	tenantID          string
	audience          string
	issuerURL         string
	additionalClients map[string]struct{}
	mu                sync.Mutex
	verifier          *oidc.IDTokenVerifier
}

func NewVerifier(tenantID, audience string, additionalClients ...string) (*Verifier, error) {
	if !uuidPattern.MatchString(tenantID) || !uuidPattern.MatchString(audience) {
		return nil, errors.New("tenant and audience must be GUIDs")
	}
	clients := make(map[string]struct{}, len(additionalClients))
	for _, client := range additionalClients {
		if !uuidPattern.MatchString(client) {
			return nil, errors.New("additional client IDs must be GUIDs")
		}
		clients[strings.ToLower(client)] = struct{}{}
	}
	tenantID = strings.ToLower(tenantID)
	return &Verifier{tenantID: tenantID, audience: strings.ToLower(audience), issuerURL: issuer(tenantID), additionalClients: clients}, nil
}

func newVerifierForIssuer(tenantID, audience, issuerURL string, additionalClients ...string) (*Verifier, error) {
	verifier, err := NewVerifier(tenantID, audience, additionalClients...)
	if err != nil {
		return nil, err
	}
	verifier.issuerURL = issuerURL
	return verifier, nil
}

func (v *Verifier) Verify(ctx context.Context, raw string) (Principal, error) {
	verifier, err := v.getVerifier(ctx)
	if err != nil {
		return Principal{}, err
	}
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return Principal{}, errors.New("token verification failed")
	}
	var claims struct {
		TenantID             string `json:"tid"`
		ObjectID             string `json:"oid"`
		Audience             string `json:"aud"`
		Issuer               string `json:"iss"`
		Version              string `json:"ver"`
		ClientID             string `json:"azp"`
		Scope                string `json:"scp"`
		IDType               string `json:"idtyp"`
		VerifiedPrimaryEmail string `json:"verified_primary_email"`
	}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, errors.New("token claims are invalid")
	}
	if !uuidPattern.MatchString(claims.TenantID) || !strings.EqualFold(claims.TenantID, v.tenantID) ||
		!uuidPattern.MatchString(claims.ObjectID) || !strings.EqualFold(claims.Audience, v.audience) ||
		claims.Version != "2.0" || !strings.EqualFold(claims.Issuer, v.issuerURL) ||
		token.Expiry.IsZero() || !token.Expiry.After(time.Now()) || claims.IDType == "app" ||
		!hasScope(claims.Scope, "access_as_user") {
		return Principal{}, errors.New("token identity is not authorized")
	}
	clientID := strings.ToLower(claims.ClientID)
	if !uuidPattern.MatchString(clientID) {
		return Principal{}, errors.New("token client is not authorized")
	}
	if !v.authorizedClient(clientID) {
		return Principal{}, errors.New("token client is not authorized")
	}
	principal := Principal{TenantID: v.tenantID, ObjectID: strings.ToLower(claims.ObjectID)}
	if strings.Contains(claims.VerifiedPrimaryEmail, "@") {
		principal.VerifiedEmail = strings.ToLower(strings.TrimSpace(claims.VerifiedPrimaryEmail))
	}
	return principal, nil
}

func (v *Verifier) authorizedClient(clientID string) bool {
	if _, ok := authorizedClients[clientID]; ok {
		return true
	}
	_, ok := v.additionalClients[clientID]
	return ok
}

func (v *Verifier) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	issuerURL := v.issuerURL
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataUnavailable, err)
	}
	v.verifier = provider.Verifier(&oidc.Config{ClientID: v.audience, SupportedSigningAlgs: []string{"RS256"}})
	return v.verifier, nil
}

func issuer(tenantID string) string {
	return "https://login.microsoftonline.com/" + tenantID + "/v2.0"
}

func hasScope(scopes, required string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == required {
			return true
		}
	}
	return false
}

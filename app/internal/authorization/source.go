package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"iq-kbteams/internal/httpx"
)

// Permission sources supply authorization decisions, rather than guesses from
// table/column names. Only deployment configuration can establish this authority.
type PermissionSubject struct {
	UserID   string `json:"userId"`
	Email    string `json:"email"`
	TenantID string `json:"tenantId"`
	ObjectID string `json:"objectId"`
	Label    string `json:"label"`
}
type ReadPermission struct {
	Schema   string   `json:"schema"`
	Relation string   `json:"relation"`
	Fields   []string `json:"fields"`
	Scope    Scope    `json:"scope"`
}
type PermissionResponse struct {
	Subject      PermissionSubject `json:"subject"`
	Allowed      *bool             `json:"allowed"`
	Revision     string            `json:"revision"`
	ClaimColumns map[string]string `json:"claimColumns,omitempty"`
	Resources    []ReadPermission  `json:"resources"`
}
type ResolvedPermissions struct {
	Rules        []Rule
	ClaimColumns map[string]string
	Revision     string
}
type PermissionSource interface {
	Resolve(context.Context, PermissionSubject) (ResolvedPermissions, error)
	Fingerprint() string
}

type HTTPPermissionSource struct {
	endpoint, token string
	client          *http.Client
	fingerprint     string
}

func NewHTTPPermissionSource(endpoint, token string) (*HTTPPermissionSource, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(endpoint) > 2048 || strings.TrimSpace(token) == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
		return nil, errors.New("native permission source requires an HTTPS endpoint and server credential")
	}
	hash := sha256.Sum256([]byte(endpoint + "\x00" + token))
	return &HTTPPermissionSource{endpoint: endpoint, token: token, fingerprint: hex.EncodeToString(hash[:]), client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (s *HTTPPermissionSource) Fingerprint() string { return s.fingerprint }
func (s *HTTPPermissionSource) Resolve(ctx context.Context, subject PermissionSubject) (ResolvedPermissions, error) {
	var empty ResolvedPermissions
	if subject.UserID == "" || subject.Email == "" || subject.TenantID == "" || subject.ObjectID == "" || subject.Label == "" {
		return empty, errors.New("permission_source_identity_required")
	}
	body, _ := json.Marshal(struct {
		Subject   PermissionSubject `json:"subject"`
		Operation string            `json:"operation"`
	}{subject, "read"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return empty, errors.New("permission_source_unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return empty, errors.New("permission_source_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return empty, errors.New("permission_source_denied")
	}
	if response.StatusCode != http.StatusOK {
		return empty, errors.New("permission_source_unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	if err != nil || len(raw) > 128<<10 {
		return empty, errors.New("permission_source_response_invalid")
	}
	policy, err := httpx.DecodeOne[PermissionResponse](raw)
	if err != nil || policy.Allowed == nil || policy.Revision == "" || len(policy.Revision) > 256 || len(policy.ClaimColumns) > 16 {
		return empty, errors.New("permission_source_response_invalid")
	}
	actual := policy.Subject
	actual.Email = strings.ToLower(strings.TrimSpace(actual.Email))
	expected := subject
	expected.Email = strings.ToLower(strings.TrimSpace(expected.Email))
	if actual != expected {
		return empty, errors.New("permission_source_identity_mismatch")
	}
	if !*policy.Allowed || len(policy.Resources) == 0 {
		return empty, errors.New("permission_source_denied")
	}
	result := ResolvedPermissions{ClaimColumns: policy.ClaimColumns, Revision: policy.Revision}
	for _, resource := range policy.Resources {
		result.Rules = append(result.Rules, Rule{Label: subject.Label, Schema: resource.Schema, Relation: resource.Relation, Fields: resource.Fields, Scope: resource.Scope, Reviewed: true})
	}
	if ValidateRules(result.Rules) != nil {
		return empty, errors.New("permission_source_response_invalid")
	}
	return result, nil
}

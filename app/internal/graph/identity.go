package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type DirectoryIdentityError struct{ State string }

func (e *DirectoryIdentityError) Error() string { return e.State }

// DirectoryEmail resolves the delegated user at the fixed Graph origin and
// binds the response to the already-verified Teams object ID. No client email
// or username fallback is accepted.
func DirectoryEmail(ctx context.Context, socket, assertion, objectID string) (string, error) {
	return directoryEmail(ctx, unixTokenExchanger{socketPath: socket}, graphHTTPClient(), graphBaseURL, assertion, objectID)
}

func directoryEmail(ctx context.Context, x TokenExchanger, client *http.Client, baseURL, assertion, objectID string) (string, error) {
	token, err := x.Exchange(ctx, assertion, "identity")
	if err != nil {
		return "", &DirectoryIdentityError{State: "directory_token_exchange_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/me?$select=id,mail,userType", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", &DirectoryIdentityError{State: "directory_unavailable"}
	}
	defer resp.Body.Close()
	var user struct {
		ID       string `json:"id"`
		Mail     string `json:"mail"`
		UserType string `json:"userType"`
	}
	if resp.StatusCode != http.StatusOK {
		state := "directory_unavailable"
		if resp.StatusCode == http.StatusForbidden {
			state = "directory_permission_denied"
		}
		if resp.StatusCode == http.StatusUnauthorized {
			state = "directory_sign_in_required"
		}
		return "", &DirectoryIdentityError{State: state}
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&user) != nil {
		return "", &DirectoryIdentityError{State: "directory_unavailable"}
	}
	if !strings.EqualFold(user.ID, objectID) {
		return "", &DirectoryIdentityError{State: "directory_identity_mismatch"}
	}
	if user.UserType != "Member" {
		return "", &DirectoryIdentityError{State: "directory_member_required"}
	}
	email := strings.ToLower(strings.TrimSpace(user.Mail))
	if !strings.Contains(email, "@") || strings.ContainsAny(email, "\r\n\x00") {
		return "", &DirectoryIdentityError{State: "directory_mail_missing"}
	}
	return email, nil
}

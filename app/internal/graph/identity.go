package graph

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// DirectoryEmail resolves the delegated user at the fixed Graph origin and
// binds the response to the already-verified Teams object ID. No client email
// or username fallback is accepted.
func DirectoryEmail(ctx context.Context, socket, assertion, objectID string) (string, error) {
	return directoryEmail(ctx, unixTokenExchanger{socketPath: socket}, graphHTTPClient(), graphBaseURL, assertion, objectID)
}

func directoryEmail(ctx context.Context, x TokenExchanger, client *http.Client, baseURL, assertion, objectID string) (string, error) {
	token, err := x.Exchange(ctx, assertion, "identity")
	if err != nil {
		return "", errors.New("directory identity consent or token exchange failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/me?$select=id,mail,userType", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("directory identity lookup failed")
	}
	defer resp.Body.Close()
	var user struct {
		ID       string `json:"id"`
		Mail     string `json:"mail"`
		UserType string `json:"userType"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&user) != nil || !strings.EqualFold(user.ID, objectID) || user.UserType != "Member" {
		return "", errors.New("directory identity does not match an organization member")
	}
	email := strings.ToLower(strings.TrimSpace(user.Mail))
	if !strings.Contains(email, "@") || strings.ContainsAny(email, "\r\n\x00") {
		return "", errors.New("directory email unavailable")
	}
	return email, nil
}

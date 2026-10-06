package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	graphBaseURL     = "https://graph.microsoft.com/v1.0"
	MaxQuestionRunes = 500
	maxSearchHits    = 3
	maxFileBytes     = 12 << 20
)

type TokenExchanger interface {
	Exchange(context.Context, string, string) (string, error)
}

type unixTokenExchanger struct{ socketPath string }

type tokenRequest struct {
	Assertion string `json:"assertion"`
	Profile   string `json:"profile"`
}

type tokenResponse struct {
	AccessToken string `json:"accessToken"`
}

func (x unixTokenExchanger) Exchange(ctx context.Context, assertion, profile string) (string, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", x.socketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	payload, err := json.Marshal(tokenRequest{Assertion: assertion, Profile: profile})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://obo/v1/obo", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return "", errors.New("delegated token exchange failed")
	}
	var token tokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&token); err != nil || token.AccessToken == "" {
		return "", errors.New("invalid token response")
	}
	return token.AccessToken, nil
}

type OneDrive struct {
	exchanger TokenExchanger
	baseURL   string
	client    *http.Client
}

type Document struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	WebURL         string `json:"webUrl"`
	Content        []byte `json:"-"`
	ParserFilename string `json:"-"`
	PlainText      bool   `json:"-"`
}

type driveItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"webUrl"`
}

type searchResponse struct {
	Value []driveItem `json:"value"`
}

func NewOneDrive(socketPath string) *OneDrive {
	return NewOneDriveWithHTTPClient(socketPath, graphHTTPClient())
}

// NewOneDriveWithHTTPClient uses a caller-provided transport while retaining
// the fixed Microsoft Graph origin. This supports controlled transports and
// integration tests without making the Graph endpoint configurable.
func NewOneDriveWithHTTPClient(socketPath string, client *http.Client) *OneDrive {
	if client == nil {
		client = graphHTTPClient()
	}
	return newOneDrive(unixTokenExchanger{socketPath: socketPath}, graphBaseURL, client)
}

func newOneDrive(exchanger TokenExchanger, baseURL string, client *http.Client) *OneDrive {
	return &OneDrive{exchanger: exchanger, baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (d *OneDrive) Check(ctx context.Context, assertion string) (string, error) {
	token, err := d.exchanger.Exchange(ctx, assertion, "onedrive")
	if err != nil {
		return "consent_required", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+"/me/drive?$select=id,driveType", nil)
	if err != nil {
		return "unavailable", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := d.client.Do(request)
	if err != nil {
		return "unavailable", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusOK:
		return "connected", nil
	case http.StatusForbidden:
		return "permission_denied", errors.New("Graph denied access to the user's drive")
	case http.StatusNotFound:
		return "not_provisioned", errors.New("user drive is not provisioned")
	case http.StatusUnauthorized:
		return "consent_required", errors.New("Graph rejected the delegated token")
	default:
		return "unavailable", errors.New("Graph drive check failed")
	}
}

// Retrieve searches only the signed-in user's OneDrive and downloads matching
// files through Graph, which reevaluates the user's delegated permissions.
// Content stays in memory and is returned only to the caller for extraction.
func (d *OneDrive) Retrieve(ctx context.Context, assertion, query string) ([]Document, error) {
	return d.RetrieveLimit(ctx, assertion, query, maxSearchHits)
}

func (d *OneDrive) RetrieveLimit(ctx context.Context, assertion, query string, limit int) ([]Document, error) {
	query = strings.TrimSpace(query)
	if query == "" || len([]rune(query)) > MaxQuestionRunes || strings.ContainsAny(query, "\x00\r\n") {
		return nil, errors.New("invalid search query")
	}
	if limit < 1 || limit > maxSearchHits {
		return nil, errors.New("invalid result limit")
	}
	token, err := d.exchanger.Exchange(ctx, assertion, "onedrive")
	if err != nil {
		return nil, err
	}
	searchTerm := strings.ReplaceAll(query, "'", "''")
	searchURL := d.baseURL + "/me/drive/root/search(q='" + url.PathEscape(searchTerm) + "')?$select=id,name,webUrl&$top=" + fmt.Sprint(limit)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	_ = response.Body.Close()
	if readErr != nil || len(body) > 1<<20 {
		return nil, errors.New("Graph search response limit exceeded")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Graph search returned status %d", response.StatusCode)
	}
	var result searchResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.New("invalid Graph search response")
	}
	if len(result.Value) > limit {
		result.Value = result.Value[:limit]
	}
	documents := make([]Document, 0, len(result.Value))
	for _, item := range result.Value {
		if item.ID == "" || len(item.Name) > 255 || !supportedFile(item.Name) || !trustedWebURL(item.URL) {
			continue
		}
		content, err := d.download(ctx, token, item.ID)
		if err != nil {
			continue
		}
		documents = append(documents, Document{ID: item.ID, Name: item.Name, WebURL: item.URL, Content: content})
	}
	return documents, nil
}

func (d *OneDrive) download(ctx context.Context, token, id string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+"/me/drive/items/"+url.PathEscape(id)+"/content", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("Graph download returned status %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxFileBytes+1))
	if err != nil || len(content) > maxFileBytes {
		return nil, errors.New("downloaded file exceeds size limit")
	}
	return content, nil
}

func supportedFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pdf", ".docx", ".pptx", ".xlsx":
		return true
	default:
		return false
	}
}

func trustedWebURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, ".sharepoint.com") || strings.HasSuffix(host, ".onedrive.com")
}

func graphHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 4 || request.URL.Scheme != "https" || (request.URL.Port() != "" && request.URL.Port() != "443") {
				return http.ErrUseLastResponse
			}
			host := strings.ToLower(request.URL.Hostname())
			if host != "graph.microsoft.com" && !strings.HasSuffix(host, ".sharepoint.com") &&
				!strings.HasSuffix(host, ".1drv.com") && !strings.HasSuffix(host, ".microsoftusercontent.com") {
				return http.ErrUseLastResponse
			}
			if host != "graph.microsoft.com" {
				request.Header.Del("Authorization")
			}
			return nil
		},
	}
}

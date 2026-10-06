package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const MaxSharePointSites = 5

var sharePointHostPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+sharepoint\.com$`)

type SharePoint struct {
	exchanger TokenExchanger
	baseURL   string
	client    *http.Client
}

type graphSite struct {
	ID     string `json:"id"`
	WebURL string `json:"webUrl"`
}

func NewSharePoint(socketPath string) *SharePoint {
	return &SharePoint{exchanger: unixTokenExchanger{socketPath: socketPath}, baseURL: graphBaseURL, client: graphHTTPClient()}
}

func newSharePoint(exchanger TokenExchanger, baseURL string, client *http.Client) *SharePoint {
	return &SharePoint{exchanger: exchanger, baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func ValidateSharePointSiteURL(raw string) (string, error) {
	if len(raw) > 1024 || strings.TrimSpace(raw) != raw {
		return "", errors.New("invalid SharePoint site URL")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return "", errors.New("invalid SharePoint site URL")
	}
	host := strings.ToLower(u.Hostname())
	if !sharePointHostPattern.MatchString(host) {
		return "", errors.New("SharePoint site must use a SharePoint Online host")
	}
	if u.Path == "" || u.Path == "/" || strings.Contains(u.Path, "//") {
		return "", errors.New("a specific SharePoint site path is required")
	}
	escapedPath := strings.TrimRight(u.EscapedPath(), "/")
	for _, segment := range strings.Split(strings.Trim(escapedPath, "/"), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\\x00") || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
			return "", errors.New("invalid SharePoint site path")
		}
	}
	return "https://" + host + escapedPath, nil
}

// Check validates the configured site and its default document library with
// the administrator's delegated token. User retrieval repeats these Graph
// calls with that user's own delegated token.
func (s *SharePoint) Check(ctx context.Context, assertion, siteURL string) (string, error) {
	canonical, err := ValidateSharePointSiteURL(siteURL)
	if err != nil {
		return "invalid_site", err
	}
	token, err := s.exchanger.Exchange(ctx, assertion, "sharepoint")
	if err != nil {
		return "consent_required", err
	}
	site, err := s.resolve(ctx, token, canonical)
	if err != nil {
		return graphFailureState(err), err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/sites/"+url.PathEscape(site.ID)+"/drive?$select=id", nil)
	if err != nil {
		return "unavailable", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := s.client.Do(request)
	if err != nil {
		return "unavailable", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusOK:
		return "connected", nil
	case http.StatusForbidden:
		return "permission_denied", errors.New("Graph denied access to the configured site")
	case http.StatusNotFound:
		return "not_found", errors.New("configured SharePoint site or document library was not found")
	case http.StatusUnauthorized:
		return "consent_required", errors.New("Graph rejected the delegated token")
	default:
		return "unavailable", errors.New("Graph SharePoint check failed")
	}
}

func (s *SharePoint) Retrieve(ctx context.Context, assertion, siteURL, query string) ([]Document, error) {
	return s.RetrieveLimit(ctx, assertion, siteURL, query, maxSearchHits)
}

func (s *SharePoint) RetrieveLimit(ctx context.Context, assertion, siteURL, query string, limit int) ([]Document, error) {
	query = strings.TrimSpace(query)
	if query == "" || len([]rune(query)) > MaxQuestionRunes || strings.ContainsAny(query, "\x00\r\n") {
		return nil, errors.New("invalid search query")
	}
	if limit < 1 || limit > maxSearchHits {
		return nil, errors.New("invalid result limit")
	}
	canonical, err := ValidateSharePointSiteURL(siteURL)
	if err != nil {
		return nil, err
	}
	token, err := s.exchanger.Exchange(ctx, assertion, "sharepoint")
	if err != nil {
		return nil, err
	}
	site, err := s.resolve(ctx, token, canonical)
	if err != nil {
		return nil, err
	}
	searchTerm := strings.ReplaceAll(query, "'", "''")
	searchURL := s.baseURL + "/sites/" + url.PathEscape(site.ID) + "/drive/root/search(q='" + url.PathEscape(searchTerm) + "')?$select=id,name,webUrl&$top=" + fmt.Sprint(limit)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	_ = response.Body.Close()
	if readErr != nil || len(body) > 1<<20 {
		return nil, errors.New("Graph search response limit exceeded")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Graph SharePoint search returned status %d", response.StatusCode)
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
		content, err := s.download(ctx, token, site.ID, item.ID)
		if err != nil {
			continue
		}
		documents = append(documents, Document{ID: site.ID + ":" + item.ID, Name: item.Name, WebURL: item.URL, Content: content})
	}
	return documents, nil
}

func (s *SharePoint) resolve(ctx context.Context, token, siteURL string) (graphSite, error) {
	u, err := url.Parse(siteURL)
	if err != nil {
		return graphSite{}, errors.New("invalid SharePoint site URL")
	}
	segments := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	for i, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return graphSite{}, errors.New("invalid SharePoint site path")
		}
		segments[i] = url.PathEscape(decoded)
	}
	endpoint := s.baseURL + "/sites/" + u.Hostname() + ":/" + strings.Join(segments, "/") + "?$select=id,webUrl"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return graphSite{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := s.client.Do(request)
	if err != nil {
		return graphSite{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return graphSite{}, err
	}
	if response.StatusCode != http.StatusOK {
		return graphSite{}, fmt.Errorf("Graph site resolution returned status %d", response.StatusCode)
	}
	var site graphSite
	if err := json.Unmarshal(body, &site); err != nil || site.ID == "" {
		return graphSite{}, errors.New("invalid Graph site response")
	}
	if site.WebURL != "" && !sameSharePointHost(site.WebURL, u.Hostname()) {
		return graphSite{}, errors.New("Graph resolved an unexpected SharePoint host")
	}
	return site, nil
}

func (s *SharePoint) download(ctx context.Context, token, siteID, itemID string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/sites/"+url.PathEscape(siteID)+"/drive/items/"+url.PathEscape(itemID)+"/content", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := s.client.Do(request)
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

func graphFailureState(err error) string {
	if strings.Contains(err.Error(), "status 401") {
		return "consent_required"
	}
	if strings.Contains(err.Error(), "status 403") {
		return "permission_denied"
	}
	if strings.Contains(err.Error(), "status 404") {
		return "not_found"
	}
	return "unavailable"
}

func sameSharePointHost(raw, expected string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Hostname(), expected) && trustedWebURL(raw)
}

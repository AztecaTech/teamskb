package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

const maxMailBodyBytes = 1 << 20

type Outlook struct {
	exchanger TokenExchanger
	baseURL   string
	client    *http.Client
}

type mailResponse struct {
	Value []struct {
		ID      string `json:"id"`
		Subject string `json:"subject"`
		WebLink string `json:"webLink"`
		Body    struct {
			Content string `json:"content"`
		} `json:"body"`
	} `json:"value"`
}

func NewOutlook(socketPath string) *Outlook {
	return newOutlook(unixTokenExchanger{socketPath: socketPath}, graphBaseURL, graphHTTPClient())
}

func newOutlook(exchanger TokenExchanger, baseURL string, client *http.Client) *Outlook {
	return &Outlook{exchanger: exchanger, baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (o *Outlook) Check(ctx context.Context, assertion string) (string, error) {
	token, err := o.exchanger.Exchange(ctx, assertion, "outlook")
	if err != nil {
		return "consent_required", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/me/messages?$top=1&$select=id", nil)
	if err != nil {
		return "unavailable", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := o.client.Do(request)
	if err != nil {
		return "unavailable", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusOK:
		return "connected", nil
	case http.StatusForbidden:
		return "permission_denied", errors.New("Graph denied access to the user's mailbox")
	case http.StatusNotFound:
		return "not_provisioned", errors.New("user mailbox is not provisioned")
	case http.StatusUnauthorized:
		return "consent_required", errors.New("Graph rejected the delegated token")
	default:
		return "unavailable", errors.New("Graph mailbox check failed")
	}
}

// Retrieve searches only the signed-in user's mailbox. The search response
// carries plain text bodies so mail can use the existing offline parser.
func (o *Outlook) Retrieve(ctx context.Context, assertion, query string, limit int) ([]Document, error) {
	query = strings.TrimSpace(query)
	if query == "" || len([]rune(query)) > MaxQuestionRunes || strings.ContainsAny(query, "\x00\r\n") {
		return nil, errors.New("invalid search query")
	}
	if limit < 1 || limit > maxSearchHits {
		return nil, errors.New("invalid result limit")
	}
	token, err := o.exchanger.Exchange(ctx, assertion, "outlook")
	if err != nil {
		return nil, err
	}
	search := `"` + strings.ReplaceAll(query, `"`, `\"`) + `"`
	endpoint := o.baseURL + "/me/messages?$search=" + url.QueryEscape(search) + "&$select=id,subject,webLink,body&$top=" + fmt.Sprint(limit)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Prefer", `outlook.body-content-type="text"`)
	response, err := o.client.Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxMailBodyBytes+1))
	_ = response.Body.Close()
	if readErr != nil || len(body) > maxMailBodyBytes {
		return nil, errors.New("Graph mail response limit exceeded")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Graph mail search returned status %d", response.StatusCode)
	}
	var result mailResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.New("invalid Graph mail response")
	}
	if len(result.Value) > limit {
		result.Value = result.Value[:limit]
	}
	documents := make([]Document, 0, len(result.Value))
	for _, item := range result.Value {
		if item.ID == "" || strings.TrimSpace(item.Subject) == "" || len(item.Subject) > 255 || strings.IndexFunc(item.Subject, unicode.IsControl) >= 0 || !trustedMailURL(item.WebLink) || len(item.Body.Content) == 0 {
			continue
		}
		documents = append(documents, Document{ID: item.ID, Name: item.Subject, WebURL: item.WebLink, Content: []byte(item.Body.Content), ParserFilename: "message.txt"})
	}
	return documents, nil
}

func trustedMailURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "outlook.office.com" || host == "outlook.office365.com"
}

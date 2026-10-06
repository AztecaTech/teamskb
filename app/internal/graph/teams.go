package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	maxChats           = 10
	maxMessagesPerChat = 20
	maxTeamsResponse   = 4 << 20
)

var htmlTagPattern = regexp.MustCompile(`(?s)<[^>]*>`)

type TeamsChats struct {
	exchanger TokenExchanger
	baseURL   string
	client    *http.Client
}

type chatListResponse struct {
	Value []struct {
		ID    string `json:"id"`
		Topic string `json:"topic"`
	} `json:"value"`
}

type chatMessagesResponse struct {
	Value []struct {
		ID      string `json:"id"`
		Type    string `json:"messageType"`
		Subject string `json:"subject"`
		WebURL  string `json:"webUrl"`
		Created string `json:"createdDateTime"`
		Body    struct {
			Content string `json:"content"`
		} `json:"body"`
		From struct {
			User struct {
				Name string `json:"displayName"`
			} `json:"user"`
		} `json:"from"`
	} `json:"value"`
}

func NewTeamsChats(socketPath string) *TeamsChats {
	return newTeamsChats(unixTokenExchanger{socketPath: socketPath}, graphBaseURL, graphHTTPClient())
}

func newTeamsChats(exchanger TokenExchanger, baseURL string, client *http.Client) *TeamsChats {
	return &TeamsChats{exchanger: exchanger, baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (t *TeamsChats) Check(ctx context.Context, assertion string) (string, error) {
	token, err := t.exchanger.Exchange(ctx, assertion, "teams")
	if err != nil {
		return "consent_required", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+"/me/chats?$top=1", nil)
	if err != nil {
		return "unavailable", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := t.client.Do(request)
	if err != nil {
		return "unavailable", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusOK:
		return "connected", nil
	case http.StatusForbidden:
		return "permission_denied", errors.New("Graph denied access to the user's Teams chats")
	case http.StatusUnauthorized:
		return "consent_required", errors.New("Graph rejected the delegated token")
	default:
		return "unavailable", errors.New("Graph Teams chat check failed")
	}
}

// Retrieve searches recent messages in the signed-in user's private and group
// chats. It examines at most ten chats and twenty messages per chat.
func (t *TeamsChats) Retrieve(ctx context.Context, assertion, query string, limit int) ([]Document, error) {
	query = strings.TrimSpace(query)
	if query == "" || len([]rune(query)) > MaxQuestionRunes || strings.ContainsAny(query, "\x00\r\n") {
		return nil, errors.New("invalid search query")
	}
	if limit < 1 || limit > maxSearchHits {
		return nil, errors.New("invalid result limit")
	}
	token, err := t.exchanger.Exchange(ctx, assertion, "teams")
	if err != nil {
		return nil, err
	}
	chats, err := t.get(ctx, token, "/me/chats?$top=10&$orderby=lastMessagePreview/createdDateTime%20desc")
	if err != nil {
		return nil, err
	}
	var chatList chatListResponse
	if err := json.Unmarshal(chats, &chatList); err != nil {
		return nil, errors.New("invalid Graph Teams chat response")
	}
	if len(chatList.Value) > maxChats {
		chatList.Value = chatList.Value[:maxChats]
	}
	terms := searchTerms(query)
	type ranked struct {
		document Document
		score    int
		created  string
	}
	var matches []ranked
	messageListsRead, messageListFailures := 0, 0
	for _, chat := range chatList.Value {
		if chat.ID == "" {
			continue
		}
		messages, err := t.get(ctx, token, "/chats/"+url.PathEscape(chat.ID)+"/messages?$top="+fmt.Sprint(maxMessagesPerChat)+"&$orderby=createdDateTime%20desc")
		if err != nil {
			messageListFailures++
			continue
		}
		var response chatMessagesResponse
		if json.Unmarshal(messages, &response) != nil {
			messageListFailures++
			continue
		}
		messageListsRead++
		if len(response.Value) > maxMessagesPerChat {
			response.Value = response.Value[:maxMessagesPerChat]
		}
		for _, message := range response.Value {
			if message.ID == "" || (message.Type != "" && message.Type != "message") || !trustedTeamsURL(message.WebURL) {
				continue
			}
			text := cleanTeamsText(message.Body.Content)
			if strings.TrimSpace(text) == "" {
				continue
			}
			score := termScore(terms, chat.Topic+" "+message.Subject+" "+text)
			if score == 0 {
				continue
			}
			name := "Teams chat message"
			if strings.TrimSpace(chat.Topic) != "" {
				name = "Teams: " + strings.TrimSpace(chat.Topic)
			}
			if message.From.User.Name != "" {
				name += " — " + message.From.User.Name
			}
			if len(name) > 255 {
				name = name[:255]
			}
			matches = append(matches, ranked{Document{ID: chat.ID + ":" + message.ID, Name: name, WebURL: message.WebURL, Content: []byte(text), ParserFilename: "message.txt"}, score, message.Created})
		}
	}
	if len(matches) == 0 && messageListsRead == 0 && messageListFailures > 0 {
		return nil, errors.New("Graph Teams message search failed")
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].created > matches[j].created
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	documents := make([]Document, 0, len(matches))
	for _, match := range matches {
		documents = append(documents, match.document)
	}
	return documents, nil
}

func (t *TeamsChats) get(ctx context.Context, token, path string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := t.client.Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTeamsResponse+1))
	_ = response.Body.Close()
	if readErr != nil || len(body) > maxTeamsResponse {
		return nil, errors.New("Graph Teams response limit exceeded")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Graph Teams request returned status %d", response.StatusCode)
	}
	return body, nil
}

func searchTerms(query string) []string {
	seen := map[string]bool{}
	var terms []string
	for _, term := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) }) {
		if len([]rune(term)) >= 3 && !seen[term] {
			seen[term] = true
			terms = append(terms, term)
		}
	}
	return terms
}

func termScore(terms []string, value string) int {
	value = strings.ToLower(value)
	score := 0
	for _, term := range terms {
		if strings.Contains(value, term) {
			score++
		}
	}
	return score
}

func cleanTeamsText(value string) string {
	value = html.UnescapeString(htmlTagPattern.ReplaceAllString(value, " "))
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, value))
}

func trustedTeamsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && strings.EqualFold(u.Hostname(), "teams.microsoft.com") && (u.Port() == "" || u.Port() == "443")
}

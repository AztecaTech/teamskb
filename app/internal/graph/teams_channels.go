package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	maxAssociatedTeams    = 5
	maxChannelsPerTeam    = 5
	maxMessagesPerChannel = 20
	maxChannelSearchBytes = 12 << 20
)

type TeamsChannels struct {
	exchanger TokenExchanger
	baseURL   string
	client    *http.Client
}

type teamListResponse struct {
	Value []struct {
		ID   string `json:"id"`
		Name string `json:"displayName"`
	} `json:"value"`
}

type channelListResponse struct {
	Value []struct {
		ID   string `json:"id"`
		Name string `json:"displayName"`
	} `json:"value"`
}

func NewTeamsChannels(socketPath string) *TeamsChannels {
	return newTeamsChannels(unixTokenExchanger{socketPath: socketPath}, graphBaseURL, graphHTTPClient())
}

func newTeamsChannels(exchanger TokenExchanger, baseURL string, client *http.Client) *TeamsChannels {
	return &TeamsChannels{exchanger: exchanger, baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (t *TeamsChannels) Check(ctx context.Context, assertion string) (string, error) {
	token, err := t.exchanger.Exchange(ctx, assertion, "teams_channels")
	if err != nil {
		return "consent_required", err
	}
	teams, err := t.get(ctx, token, "/me/teamwork/associatedTeams", nil)
	if err != nil {
		return graphFailureState(err), err
	}
	var result teamListResponse
	if err := json.Unmarshal(teams, &result); err != nil {
		return "unavailable", errors.New("invalid Graph associated Teams response")
	}
	if len(result.Value) == 0 {
		return "connected", nil
	}
	channels, err := t.get(ctx, token, "/teams/"+url.PathEscape(result.Value[0].ID)+"/allChannels?$top=1&$select=id,displayName", nil)
	if err != nil {
		return graphFailureState(err), err
	}
	var channelResult channelListResponse
	if err := json.Unmarshal(channels, &channelResult); err != nil {
		return "unavailable", errors.New("invalid Graph channels response")
	}
	if len(channelResult.Value) > 0 {
		_, err := t.get(ctx, token, "/teams/"+url.PathEscape(result.Value[0].ID)+"/channels/"+url.PathEscape(channelResult.Value[0].ID)+"/messages?$top=1&$orderby=createdDateTime%20desc", nil)
		if err != nil {
			return graphFailureState(err), err
		}
	}
	return "connected", nil
}

// Retrieve searches recent root messages in teams the signed-in user belongs to,
// including host teams for shared-channel memberships. It inspects at most five
// teams, five channels per team, and twenty messages
// per channel, with a twelve MiB aggregate Graph response cap.
func (t *TeamsChannels) Retrieve(ctx context.Context, assertion, query string, limit int) ([]Document, error) {
	query = strings.TrimSpace(query)
	if query == "" || len([]rune(query)) > MaxQuestionRunes || strings.ContainsAny(query, "\x00\r\n") {
		return nil, errors.New("invalid search query")
	}
	if limit < 1 || limit > maxSearchHits {
		return nil, errors.New("invalid result limit")
	}
	token, err := t.exchanger.Exchange(ctx, assertion, "teams_channels")
	if err != nil {
		return nil, err
	}
	budget := maxChannelSearchBytes
	teamsBody, err := t.get(ctx, token, "/me/teamwork/associatedTeams", &budget)
	if err != nil {
		return nil, err
	}
	var teams teamListResponse
	if err := json.Unmarshal(teamsBody, &teams); err != nil {
		return nil, errors.New("invalid Graph associated Teams response")
	}
	if len(teams.Value) > maxAssociatedTeams {
		teams.Value = teams.Value[:maxAssociatedTeams]
	}
	terms := searchTerms(query)
	type ranked struct {
		document Document
		score    int
		created  string
	}
	var matches []ranked
	messageListsRead, failures := 0, 0
	for _, team := range teams.Value {
		if team.ID == "" || budget <= 0 {
			break
		}
		channelsBody, err := t.get(ctx, token, "/teams/"+url.PathEscape(team.ID)+"/allChannels?$top=5&$select=id,displayName,membershipType", &budget)
		if err != nil {
			failures++
			continue
		}
		var channels channelListResponse
		if json.Unmarshal(channelsBody, &channels) != nil {
			failures++
			continue
		}
		if len(channels.Value) > maxChannelsPerTeam {
			channels.Value = channels.Value[:maxChannelsPerTeam]
		}
		for _, channel := range channels.Value {
			if channel.ID == "" || budget <= 0 {
				break
			}
			messagesBody, err := t.get(ctx, token, "/teams/"+url.PathEscape(team.ID)+"/channels/"+url.PathEscape(channel.ID)+"/messages?$top="+fmt.Sprint(maxMessagesPerChannel)+"&$orderby=createdDateTime%20desc", &budget)
			if err != nil {
				failures++
				continue
			}
			var messages chatMessagesResponse
			if json.Unmarshal(messagesBody, &messages) != nil {
				failures++
				continue
			}
			messageListsRead++
			if len(messages.Value) > maxMessagesPerChannel {
				messages.Value = messages.Value[:maxMessagesPerChannel]
			}
			for _, message := range messages.Value {
				if message.ID == "" || (message.Type != "" && message.Type != "message") || !trustedTeamsURL(message.WebURL) {
					continue
				}
				text := cleanTeamsText(message.Body.Content)
				if text == "" {
					continue
				}
				score := termScore(terms, team.Name+" "+channel.Name+" "+message.Subject+" "+text)
				if score == 0 {
					continue
				}
				name := "Teams channel message"
				if team.Name != "" {
					name = "Teams: " + team.Name
				}
				if channel.Name != "" {
					name += " / " + channel.Name
				}
				if len(name) > 255 {
					name = name[:255]
				}
				matches = append(matches, ranked{Document{ID: team.ID + ":" + channel.ID + ":" + message.ID, Name: name, WebURL: message.WebURL, Content: []byte(text), ParserFilename: "message.txt"}, score, message.Created})
			}
		}
	}
	if len(matches) == 0 && messageListsRead == 0 && failures > 0 {
		return nil, errors.New("Graph Teams channel search failed")
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

func (t *TeamsChannels) get(ctx context.Context, token, path string, budget *int) ([]byte, error) {
	maxBytes := maxTeamsResponse
	if budget != nil && *budget < maxBytes {
		maxBytes = *budget
	}
	if maxBytes <= 0 {
		return nil, errors.New("Graph Teams response budget exceeded")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := t.client.Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	_ = response.Body.Close()
	if readErr != nil || len(body) > maxBytes {
		return nil, errors.New("Graph Teams response limit exceeded")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Graph Teams request returned status %d", response.StatusCode)
	}
	if budget != nil {
		*budget -= len(body)
	}
	return body, nil
}

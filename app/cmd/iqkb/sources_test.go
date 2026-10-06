package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSharePointSourceConfigIsValidatedAndToggleable(t *testing.T) {
	db := testDB(t)
	handler := sourceHandler(db)

	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodPut, "/api/admin/sources/sharepoint", strings.NewReader(`{"enabled":true,"siteUrls":["https://outside.example/sites/hr"]}`)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid site status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	if enabled, err := sourceEnabled(db); err != nil || enabled {
		t.Fatalf("invalid source enabled=%v err=%v", enabled, err)
	}

	configured := httptest.NewRecorder()
	handler.ServeHTTP(configured, httptest.NewRequest(http.MethodPut, "/api/admin/sources/sharepoint", strings.NewReader(`{"enabled":true,"siteUrls":["https://tenant.sharepoint.com/sites/hr","https://tenant.sharepoint.com/sites/hr"]}`)))
	if configured.Code != http.StatusOK {
		t.Fatalf("valid site status=%d body=%s", configured.Code, configured.Body.String())
	}
	sites, err := sharePointSites(db)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	if enabled, err := sourceEnabled(db); err != nil || !enabled {
		t.Fatalf("configured source enabled=%v err=%v", enabled, err)
	}

	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, httptest.NewRequest(http.MethodGet, "/api/admin/sources", nil))
	var result struct {
		Sources []struct {
			ID       string   `json:"id"`
			Enabled  bool     `json:"enabled"`
			SiteURLs []string `json:"siteUrls"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if listed.Code != http.StatusOK || len(result.Sources) != 5 || result.Sources[1].ID != "user-sharepoint" || !result.Sources[1].Enabled || len(result.Sources[1].SiteURLs) != 1 || result.Sources[2].ID != "user-outlook" || result.Sources[2].Enabled || result.Sources[3].ID != "user-teams-chats" || result.Sources[3].Enabled || result.Sources[4].ID != "user-teams-channels" || result.Sources[4].Enabled {
		t.Fatalf("unexpected source listing: %s", listed.Body.String())
	}
	mailEnabled := httptest.NewRecorder()
	handler.ServeHTTP(mailEnabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/outlook", strings.NewReader(`{"enabled":true}`)))
	if mailEnabled.Code != http.StatusOK {
		t.Fatalf("Outlook enable status=%d body=%s", mailEnabled.Code, mailEnabled.Body.String())
	}
	if enabled, err := outlookEnabled(db); err != nil || !enabled {
		t.Fatalf("Outlook enabled=%v err=%v", enabled, err)
	}
	if enabled, err := sourceEnabled(db); err != nil || !enabled {
		t.Fatalf("source enabled=%v err=%v", enabled, err)
	}
	chatEnabled := httptest.NewRecorder()
	handler.ServeHTTP(chatEnabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/teams-chats", strings.NewReader(`{"enabled":true}`)))
	if chatEnabled.Code != http.StatusOK {
		t.Fatalf("Teams chats enable status=%d body=%s", chatEnabled.Code, chatEnabled.Body.String())
	}
	if enabled, err := teamsChatsEnabled(db); err != nil || !enabled {
		t.Fatalf("Teams chats enabled=%v err=%v", enabled, err)
	}
	channelsEnabled := httptest.NewRecorder()
	handler.ServeHTTP(channelsEnabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/teams-channels", strings.NewReader(`{"enabled":true}`)))
	if channelsEnabled.Code != http.StatusOK {
		t.Fatalf("Teams channels enable status=%d body=%s", channelsEnabled.Code, channelsEnabled.Body.String())
	}
	if enabled, err := teamsChannelsEnabled(db); err != nil || !enabled {
		t.Fatalf("Teams channels enabled=%v err=%v", enabled, err)
	}

	disabled := httptest.NewRecorder()
	handler.ServeHTTP(disabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/sharepoint", strings.NewReader(`{"enabled":false,"siteUrls":["https://tenant.sharepoint.com/sites/hr"]}`)))
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable status=%d", disabled.Code)
	}
	if enabled, err := sourceEnabled(db); err != nil || !enabled {
		t.Fatalf("Outlook should keep sources enabled=%v err=%v", enabled, err)
	}
	mailDisabled := httptest.NewRecorder()
	handler.ServeHTTP(mailDisabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/outlook", strings.NewReader(`{"enabled":false}`)))
	if mailDisabled.Code != http.StatusOK {
		t.Fatalf("Outlook disable status=%d", mailDisabled.Code)
	}
	chatsDisabled := httptest.NewRecorder()
	handler.ServeHTTP(chatsDisabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/teams-chats", strings.NewReader(`{"enabled":false}`)))
	if chatsDisabled.Code != http.StatusOK {
		t.Fatalf("Teams chats disable status=%d", chatsDisabled.Code)
	}
	channelsDisabled := httptest.NewRecorder()
	handler.ServeHTTP(channelsDisabled, httptest.NewRequest(http.MethodPut, "/api/admin/sources/teams-channels", strings.NewReader(`{"enabled":false}`)))
	if channelsDisabled.Code != http.StatusOK {
		t.Fatalf("Teams channels disable status=%d", channelsDisabled.Code)
	}
	if enabled, err := sourceEnabled(db); err != nil || enabled {
		t.Fatalf("all sources disabled=%v err=%v", enabled, err)
	}
}

func TestSharePointSourceRequiresSitesWhenEnabled(t *testing.T) {
	db := testDB(t)
	handler := sourceHandler(db)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/sources/sharepoint", strings.NewReader(`{"enabled":true,"siteUrls":[]}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("empty enabled source status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPostgresSourceNeedsConfiguredDatabaseAndAppearsWhenConfigured(t *testing.T) {
	db := testDB(t)
	request := func(handler http.Handler) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/sources/postgres", strings.NewReader(`{"enabled":true}`)))
		return response
	}
	if response := request(sourceHandler(db, false)); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured PostgreSQL enable status=%d body=%s", response.Code, response.Body.String())
	}
	if enabled, err := postgresEnabled(db); err != nil || enabled {
		t.Fatalf("unconfigured PostgreSQL source enabled=%v err=%v", enabled, err)
	}
	response := httptest.NewRecorder()
	sourceHandler(db, true).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/sources", nil))
	var listing struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(listing.Sources) != 6 || listing.Sources[5].ID != "user-postgres" {
		t.Fatalf("configured source listing status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request(sourceHandler(db, true)); response.Code != http.StatusOK {
		t.Fatalf("configured PostgreSQL enable status=%d body=%s", response.Code, response.Body.String())
	}
	if enabled, err := postgresEnabled(db); err != nil || !enabled {
		t.Fatalf("configured PostgreSQL source enabled=%v err=%v", enabled, err)
	}
}

func TestSourceLimitsDivideAnswerBudgetAcrossEnabledSources(t *testing.T) {
	all := sourceLimits(5, []bool{true, true, true, true, true})
	sum := 0
	for _, limit := range all {
		sum += limit
		if limit != 1 {
			t.Fatalf("five enabled sources got quota %v", all)
		}
	}
	if sum != 5 {
		t.Fatalf("total quota=%d", sum)
	}
	six := sourceLimits(6, []bool{true, true, true, true, true, true})
	if sumSourceLimits(six) != 6 || six[5] == 0 {
		t.Fatalf("PostgreSQL did not receive a slot with all six sources: %v", six)
	}
	for _, limit := range sourceLimits(6, []bool{true}) {
		if limit > 3 {
			t.Fatalf("single source exceeded per-family cap: %v", sourceLimits(6, []bool{true}))
		}
	}
	two := sourceLimits(5, []bool{true, false, true, false, false})
	if two[0] != 3 || two[2] != 2 || two[1]+two[3]+two[4] != 0 {
		t.Fatalf("unexpected two-source quotas: %v", two)
	}
}

func TestSetupReadinessAcceptsSharePointAndRequiresCurrentModelCheck(t *testing.T) {
	db := testDB(t)
	key := bytes.Repeat([]byte{9}, 32)
	provider := providerHandler(db, testProviderAPIKey, key)
	first := httptest.NewRecorder()
	provider.ServeHTTP(first, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(`{"provider":"openai","model":"gpt-test"}`)))
	if first.Code != http.StatusOK {
		t.Fatal(first.Body.String())
	}
	fingerprint, err := modelFingerprint(db, testProviderAPIKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key,value) VALUES('model_test_fingerprint',?)`, []byte(fingerprint)); err != nil {
		t.Fatal(err)
	}
	if ready, err := setupReady(db, testProviderAPIKey, key); err != nil || ready {
		t.Fatalf("setup ready without sources=%v err=%v", ready, err)
	}
	source := httptest.NewRecorder()
	sourceHandler(db).ServeHTTP(source, httptest.NewRequest(http.MethodPut, "/api/admin/sources/sharepoint", strings.NewReader(`{"enabled":true,"siteUrls":["https://tenant.sharepoint.com/sites/hr"]}`)))
	if source.Code != http.StatusOK {
		t.Fatal(source.Body.String())
	}
	if ready, err := setupReady(db, testProviderAPIKey, key); err != nil || !ready {
		t.Fatalf("setup ready with SharePoint=%v err=%v", ready, err)
	}
	updated := httptest.NewRecorder()
	provider.ServeHTTP(updated, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(`{"provider":"openai","model":"gpt-next"}`)))
	if updated.Code != http.StatusOK {
		t.Fatal(updated.Body.String())
	}
	if ready, err := setupReady(db, testProviderAPIKey, key); err != nil || ready {
		t.Fatalf("setup ready after provider change=%v err=%v", ready, err)
	}
}

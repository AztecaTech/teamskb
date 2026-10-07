package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"iq-kbteams/internal/answer"
	"iq-kbteams/internal/graph"
	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/parserclient"
	"iq-kbteams/internal/postgres"
)

const (
	maxPromptChars     = 80_000
	maxSourceDocuments = 6
)

var answerCitationPattern = regexp.MustCompile(`\[S([0-9]+)\]`)
var answerCitationTokenPattern = regexp.MustCompile(`\[S[^\]\r\n]*\]`)

type askRequest struct {
	Question string `json:"question"`
	Scope    string `json:"scope,omitempty"`
}

type answerSource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Kind string `json:"kind,omitempty"`
}

type askRuntime struct {
	retrieve          func(context.Context, *sql.DB, identity.Principal, string, string, *postgres.ToolSelection) (retrievedSources, int, error)
	selectTool        func(context.Context, string, string, string, string, string) (string, error)
	postgresAvailable bool
	postgres          *postgres.Connector
	modelAPIKey       string
	oboSocket         string
	modelAttemptLimit int
	admission         *askAdmissionGate
	extract           func(context.Context, string, []byte) (string, error)
	generate          func(context.Context, string, string, string, string, string) (string, error)
}

type retrievedSources struct {
	documents     []graph.Document
	records       []postgres.BusinessRecord
	clarification *postgres.ProfileClarification
	documentKinds []string
	diagnostics   []sourceSearchStatus
}

func askHandler(db *sql.DB, encryptionKey []byte, oboSocket, parserSocket string, pg *postgres.Connector, apiKey string) http.HandlerFunc {
	return askHandlerWithModelAttemptLimit(db, encryptionKey, oboSocket, parserSocket, pg, apiKey, defaultMonthlyModelAttemptLimit)
}

func askHandlerWithModelAttemptLimit(db *sql.DB, encryptionKey []byte, oboSocket, parserSocket string, pg *postgres.Connector, apiKey string, modelAttemptLimit int) http.HandlerFunc {
	return askHandlerWithControls(db, encryptionKey, oboSocket, parserSocket, pg, apiKey, modelAttemptLimit, nil)
}

func askHandlerWithControls(db *sql.DB, encryptionKey []byte, oboSocket, parserSocket string, pg *postgres.Connector, apiKey string, modelAttemptLimit int, admission *askAdmissionGate) http.HandlerFunc {
	return askHandlerWithRuntime(db, encryptionKey, askRuntime{
		retrieve: func(ctx context.Context, db *sql.DB, principal identity.Principal, assertion, question string, selection *postgres.ToolSelection) (retrievedSources, int, error) {
			return retrieveEnabledSources(ctx, db, encryptionKey, pg, principal, oboSocket, assertion, question, selection)
		},
		selectTool:        answer.SelectTool,
		postgresAvailable: pg != nil,
		postgres:          pg,
		modelAPIKey:       apiKey,
		oboSocket:         oboSocket,
		modelAttemptLimit: modelAttemptLimit,
		admission:         admission,
		extract: func(ctx context.Context, filename string, content []byte) (string, error) {
			return parserclient.Extract(ctx, parserSocket, filename, content)
		},
		generate: func(ctx context.Context, provider, model, baseURL, _ string, prompt string) (string, error) {
			return answer.Generate(ctx, provider, model, baseURL, apiKey, prompt)
		},
	})
}

func askHandlerWithRuntime(db *sql.DB, encryptionKey []byte, runtime askRuntime) http.HandlerFunc {
	if runtime.modelAttemptLimit < 1 {
		runtime.modelAttemptLimit = defaultMonthlyModelAttemptLimit
	}
	if runtime.admission == nil {
		runtime.admission = newAskAdmissionGate(maxConcurrentAsks, maxConcurrentAsksPerUser)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
		if err != nil || len(body) > 16<<10 {
			jsonResponse(w, http.StatusRequestEntityTooLarge, `{"error":"request_too_large"}`)
			return
		}
		request, err := httpx.DecodeOne[askRequest](body)
		question := strings.TrimSpace(request.Question)
		if err != nil || question == "" || len([]rune(question)) > graph.MaxQuestionRunes || strings.IndexFunc(question, unicode.IsControl) >= 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_question"}`)
			return
		}
		if request.Scope == "" {
			request.Scope = "all"
		}
		if request.Scope != "all" && request.Scope != "database" && request.Scope != "microsoft" {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_search_scope"}`)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), searchScopeKey{}, request.Scope))
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		var requestBytes [16]byte
		if _, err := rand.Read(requestBytes[:]); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		requestID := hex.EncodeToString(requestBytes[:])
		started := time.Now()
		defer func() {
			slog.Info("search completed", "requestId", requestID, "scope", request.Scope, "durationMs", time.Since(started).Milliseconds())
		}()
		w.Header().Set("X-Request-ID", requestID)
		outcome := "error"
		sourceCount := 0
		userKey := strings.ToLower(principal.TenantID + ":" + principal.ObjectID)
		releaseAdmission, admitted := runtime.admission.acquire(userKey)
		if !admitted {
			outcome = "concurrency_limited"
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"too_many_concurrent_requests"}`)
			return
		}
		defer releaseAdmission()
		var active []byte
		if err := db.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key='setup_activated'`).Scan(&active); err != nil || string(active) != "1" {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"setup_incomplete"}`)
			return
		}
		enabled, err := sourceEnabled(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if !enabled {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"no_sources_enabled"}`)
			return
		}
		configuration, err := loadModelConfig(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_not_configured"}`)
			return
		}
		if runtime.modelAPIKey == "" {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_not_configured"}`)
			return
		}
		if !modelTested(db, runtime.modelAPIKey, encryptionKey) {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_check_required"}`)
			return
		}
		reserved, err := reserveDailyAsk(r.Context(), db, principal.TenantID, principal.ObjectID)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if !reserved {
			outcome = "quota_exceeded"
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"daily_limit_reached"}`)
			return
		}
		defer func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
			defer cancel()
			recordAskAudit(auditCtx, db, requestID, principal.TenantID+":"+principal.ObjectID, outcome, sourceCount)
		}()
		scheme, assertion, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestProcessingTimeout)
		defer cancel()
		var selection *postgres.ToolSelection
		selectionFailure := 0
		databaseStatus := "not_selected"
		postgresActive, postgresErr := postgresEnabled(db)
		if request.Scope != "microsoft" && postgresErr == nil && postgresActive && principal.DirectoryEmailStatus == "deferred" {
			principal.DirectoryEmailStatus = "directory_unavailable"
			if email, lookupErr := graph.DirectoryEmail(ctx, runtime.oboSocket, assertion, principal.ObjectID); lookupErr == nil {
				principal.VerifiedEmail = email
				principal.DirectoryEmailStatus = "resolved"
			}
		}
		if request.Scope != "microsoft" {
			databaseStatus = "disabled"
		}
		if request.Scope != "microsoft" && postgresErr == nil && postgresActive && !runtime.postgresAvailable {
			databaseStatus = "not_configured"
			selectionFailure = 1
		}
		if request.Scope != "microsoft" && postgresErr == nil && postgresActive && runtime.postgresAvailable {
			databaseStatus = "no_matching_query"
			catalogStarted := time.Now()
			tools, catalogErr := approvedPostgresToolsForUser(ctx, db, encryptionKey, runtime.postgres, principal)
			slog.Info("search stage completed", "requestId", requestID, "stage", "database_catalog", "durationMs", time.Since(catalogStarted).Milliseconds())
			if catalogErr != nil || len(tools) == 0 {
				selectionFailure = 1
				databaseStatus = "no_authorized_queries"
			} else if len(tools) == 1 && (len(tools[0].ProfileConfig) == 0 || string(tools[0].ProfileConfig) == "{}") {
				selection = &postgres.ToolSelection{ToolID: tools[0].ID, Limit: 3}
			} else if runtime.selectTool == nil {
				selectionFailure = 1
				databaseStatus = "query_selection_failed"
			} else {
				selectionPrompt, promptErr := postgres.SelectionPrompt(question, tools)
				if promptErr != nil {
					selectionFailure = 1
				} else {
					reserved, reserveErr := reserveMonthlyModelAttempt(ctx, db, runtime.modelAttemptLimit)
					if reserveErr != nil {
						jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_budget_unavailable"}`)
						return
					}
					if !reserved {
						outcome = "model_budget_exceeded"
						jsonResponse(w, http.StatusTooManyRequests, `{"error":"monthly_model_limit_reached"}`)
						return
					}
					selectionStarted := time.Now()
					raw, selectErr := runtime.selectTool(ctx, configuration.Provider, configuration.Model, configuration.BaseURL, runtime.modelAPIKey, selectionPrompt)
					slog.Info("search stage completed", "requestId", requestID, "stage", "query_selection", "durationMs", time.Since(selectionStarted).Milliseconds())
					if selectErr != nil {
						selectionFailure = 1
						databaseStatus = "query_selection_failed"
					} else if selection, err = postgres.ParseToolSelection(raw, tools); err != nil {
						selectionFailure = 1
						selection = nil
						databaseStatus = "query_selection_failed"
					}
				}
			}
		}
		ctx = context.WithValue(ctx, databaseSelectionStatusKey{}, databaseStatus)
		retrievalStarted := time.Now()
		retrieved, sourceFailures, err := runtime.retrieve(ctx, db, principal, assertion, question, selection)
		slog.Info("search stage completed", "requestId", requestID, "stage", "retrieval", "durationMs", time.Since(retrievalStarted).Milliseconds())
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		sourceFailures += selectionFailure
		searchInfo := map[string]any{"scope": request.Scope, "database": databaseStatus, "sources": retrieved.diagnostics}
		if selection != nil {
			searchInfo["database"] = "searched"
			for _, status := range retrieved.diagnostics {
				if status.Source == "database" {
					searchInfo["database"] = status.Status
				}
			}
		}
		for _, status := range retrieved.diagnostics {
			slog.Info("source search completed", "requestId", requestID, "scope", request.Scope, "source", status.Source, "status", status.Status, "results", status.Results)
		}
		if sourceFailures > 0 {
			searchInfo["warning"] = "Some selected sources could not be searched. The answer may be incomplete."
		}
		if retrieved.clarification != nil {
			outcome = "clarification"
			writeJSON(w, http.StatusOK, map[string]any{"clarification": retrieved.clarification, "sources": []answerSource{}, "search": searchInfo})
			return
		}
		if len(retrieved.documents)+len(retrieved.records) == 0 {
			if sourceFailures > 0 {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "source_unavailable", "search": searchInfo})
				return
			}
			outcome = "no_results"
			writeJSON(w, http.StatusOK, map[string]any{"answer": "I could not find an answer in your selected sources.", "sources": []answerSource{}, "search": searchInfo})
			return
		}
		var excerpts bytes.Buffer
		sources := make([]answerSource, 0, len(retrieved.documents)+len(retrieved.records))
		for documentIndex, document := range retrieved.documents {
			filename := document.Name
			if document.ParserFilename != "" {
				filename = document.ParserFilename
			}
			var text string
			var err error
			if document.PlainText {
				text = string(document.Content)
			} else {
				text, err = runtime.extract(ctx, filename, document.Content)
			}
			if err != nil || strings.TrimSpace(text) == "" {
				continue
			}
			text = escapeSourceCitationTokens(text)
			index := len(sources) + 1
			remaining := maxPromptChars - excerpts.Len()
			if remaining <= 0 {
				break
			}
			if len(text) > remaining {
				text = text[:remaining]
				for !utf8.ValidString(text) {
					text = text[:len(text)-1]
				}
			}
			name := escapeSourceCitationTokens(document.Name)
			_, _ = fmt.Fprintf(&excerpts, "[S%d] File: %s\n%s\n\n", index, name, text)
			kind := "microsoft"
			if documentIndex < len(retrieved.documentKinds) {
				kind = retrieved.documentKinds[documentIndex]
			}
			sources = append(sources, answerSource{ID: fmt.Sprintf("S%d", index), Name: document.Name, URL: safeCitationURL(document.WebURL), Kind: kind})
		}
		for _, record := range retrieved.records {
			remaining := maxPromptChars - excerpts.Len()
			if remaining <= 0 {
				break
			}
			attributes, _ := json.Marshal(record.Attributes)
			text := fmt.Sprintf("Business record type: %s\nStable ID: %s\nDisplay name: %s\nRelevance: %.3f\nApproved attributes: %s", record.Type, record.ID, record.DisplayName, record.Relevance, attributes)
			text = escapeSourceCitationTokens(text)
			if len(text) > remaining {
				text = text[:remaining]
				for !utf8.ValidString(text) {
					text = text[:len(text)-1]
				}
			}
			index := len(sources) + 1
			name := record.DisplayName
			if name == "" {
				name = record.Type
			}
			name = escapeSourceCitationTokens(name)
			_, _ = fmt.Fprintf(&excerpts, "[S%d] Business record: %s\n%s\n\n", index, name, text)
			sources = append(sources, answerSource{ID: fmt.Sprintf("S%d", index), Name: name, URL: safeCitationURL(record.SourceURL), Kind: "database"})
		}
		if len(sources) == 0 {
			outcome = "extraction_failed"
			jsonResponse(w, http.StatusUnprocessableEntity, `{"error":"source_extraction_failed"}`)
			return
		}
		prompt := "Question:\n" + question + "\n\nSource excerpts:\n" + excerpts.String()
		reserved, reserveErr := reserveMonthlyModelAttempt(ctx, db, runtime.modelAttemptLimit)
		if reserveErr != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_budget_unavailable"}`)
			return
		}
		if !reserved {
			outcome = "model_budget_exceeded"
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"monthly_model_limit_reached"}`)
			return
		}
		modelStarted := time.Now()
		response, err := runtime.generate(ctx, configuration.Provider, configuration.Model, configuration.BaseURL, runtime.modelAPIKey, prompt)
		slog.Info("search stage completed", "requestId", requestID, "stage", "answer_model", "durationMs", time.Since(modelStarted).Milliseconds())
		if err != nil {
			jsonResponse(w, http.StatusBadGateway, `{"error":"model_unavailable"}`)
			return
		}
		if !answerCitationsValid(response, sources) {
			response = "I could not find an answer in the connected sources."
		}
		sourceCount = len(sources)
		outcome = "answered"
		writeJSON(w, http.StatusOK, map[string]any{"answer": response, "sources": sources, "search": searchInfo})
	}
}

func safeCitationURL(raw string) string {
	if len(raw) == 0 || len(raw) > 2048 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	return u.String()
}

func answerCitationsValid(response string, sources []answerSource) bool {
	tokens := answerCitationTokenPattern.FindAllString(response, -1)
	if len(tokens) == 0 {
		return isCitationFreeAbstention(response)
	}
	validTokens := 0
	for _, token := range tokens {
		match := answerCitationPattern.FindStringSubmatch(token)
		if len(match) != 2 {
			return false
		}
		index := 0
		if _, err := fmt.Sscanf(match[1], "%d", &index); err != nil || index < 1 || index > len(sources) || match[1] != fmt.Sprint(index) || sources[index-1].ID != token[1:len(token)-1] {
			return false
		}
		validTokens++
	}
	return validTokens > 0
}

func escapeSourceCitationTokens(text string) string {
	return answerCitationTokenPattern.ReplaceAllStringFunc(text, func(token string) string {
		return "(" + token[1:len(token)-1] + ")"
	})
}

func isCitationFreeAbstention(response string) bool {
	text := strings.ToLower(strings.TrimSpace(response))
	text = strings.TrimRight(text, ".!? ")
	return text == "i could not find an answer in the connected sources" || text == "i could not find that in the connected sources"
}

func retrieveEnabledSources(ctx context.Context, db *sql.DB, encryptionKey []byte, pg *postgres.Connector, principal identity.Principal, oboSocket, assertion, question string, selection *postgres.ToolSelection) (retrievedSources, int, error) {
	active := make([]bool, 6)
	checks := []func(*sql.DB) (bool, error){oneDriveEnabled, sharePointEnabled, outlookEnabled, teamsChatsEnabled, teamsChannelsEnabled, postgresEnabled}
	for i, check := range checks {
		value, err := check(db)
		if err != nil {
			return retrievedSources{}, 0, err
		}
		active[i] = value && scopeIncludes(searchScope(ctx), i)
	}
	limits := sourceLimits(maxSourceDocuments, active)
	documents := make([]graph.Document, 0, maxSourceDocuments)
	documentKinds := make([]string, 0, maxSourceDocuments)
	records := make([]postgres.BusinessRecord, 0)
	failures := 0
	names := []string{"onedrive", "sharepoint", "outlook", "teams-chats", "teams-channels", "database"}
	diagnostics := make([]sourceSearchStatus, 0, 6)
	add := func(found []graph.Document, err error) {
		if err != nil {
			failures++
		}
		documents = append(documents, found...)
		for range found {
			documentKinds = append(documentKinds, "database")
		}
	}
	jobs := []func() ([]graph.Document, error){
		func() ([]graph.Document, error) {
			return graph.NewOneDrive(oboSocket).RetrieveLimit(ctx, assertion, question, limits[0])
		},
		func() ([]graph.Document, error) {
			sites, err := sharePointSites(db)
			if err != nil {
				return nil, err
			}
			connector := graph.NewSharePoint(oboSocket)
			var found []graph.Document
			var failed error
			for _, site := range sites {
				hits, err := connector.RetrieveLimit(ctx, assertion, site, question, limits[1]-len(found))
				if err != nil {
					failed = err
					continue
				}
				found = append(found, hits...)
				if len(found) >= limits[1] {
					break
				}
			}
			return found, failed
		},
		func() ([]graph.Document, error) {
			return graph.NewOutlook(oboSocket).Retrieve(ctx, assertion, question, limits[2])
		},
		func() ([]graph.Document, error) {
			return graph.NewTeamsChats(oboSocket).Retrieve(ctx, assertion, question, limits[3])
		},
		func() ([]graph.Document, error) {
			return graph.NewTeamsChannels(oboSocket).Retrieve(ctx, assertion, question, limits[4])
		},
	}
	type result struct {
		documents []graph.Document
		err       error
	}
	results := make([]result, 5)
	var workers sync.WaitGroup
	for i, job := range jobs {
		if !active[i] {
			continue
		}
		workers.Add(1)
		go func(i int, job func() ([]graph.Document, error)) {
			defer workers.Done()
			results[i].documents, results[i].err = job()
		}(i, job)
	}
	workers.Wait()
	for i, entry := range results {
		if !active[i] {
			continue
		}
		state := "no_results"
		if len(entry.documents) > 0 {
			state = "searched"
		}
		if entry.err != nil {
			failures++
			state = "failed"
			if len(entry.documents) > 0 {
				state = "partial"
			}
		}
		diagnostics = append(diagnostics, sourceSearchStatus{Source: names[i], Status: state, Results: len(entry.documents)})
		documents = append(documents, entry.documents...)
		for range entry.documents {
			documentKinds = append(documentKinds, "microsoft")
		}
	}
	dbFailuresBefore := failures
	if active[5] && pg == nil {
		failures++
	} else if active[5] && selection != nil && limits[5] > 0 {
		pg, databaseIdentity, password, err := postgresAccess(ctx, db, encryptionKey, pg, principal)
		tools, catalogErr := postgres.Catalog(db)
		var tool postgres.QueryTool
		toolFound := false
		if catalogErr == nil {
			for _, item := range tools {
				if item.ID == selection.ToolID {
					tool, toolFound = item, true
					break
				}
			}
		}
		if err != nil || catalogErr != nil || !toolFound {
			failures++
		} else {
			limit := min(selection.Limit, limits[5])
			if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" {
				if !postgresProfilesReady(ctx, db, pg, principal.TenantID, tools) {
					failures++
				} else {
					var profile postgres.BusinessProfile
					if json.Unmarshal(tool.ProfileConfig, &profile) != nil {
						failures++
					} else {
						term := selection.Term
						if profile.Capability == "related_list" {
							found, candidates, searchErr := pg.SearchRelatedProfile(ctx, databaseIdentity, password, term, limit, selection.Filters, profile)
							if searchErr != nil {
								failures++
							} else if len(candidates) > 1 {
								return retrievedSources{documents: documents, documentKinds: documentKinds, diagnostics: diagnostics, clarification: &postgres.ProfileClarification{Kind: "ambiguous_entity", Question: "Which matching record did you mean?", Candidates: candidates}}, failures, nil
							} else {
								records = append(records, found...)
							}
						} else {
							found, searchErr := pg.SearchProfile(ctx, databaseIdentity, password, term, limit, profile)
							if searchErr != nil {
								failures++
							} else {
								records = append(records, found...)
								if profile.Capability == "entity_lookup" && len(found) > 1 {
									candidates := make([]postgres.ProfileCandidate, 0, len(found))
									for _, record := range found {
										candidates = append(candidates, postgres.ProfileCandidate{ID: record.ID, DisplayName: record.DisplayName})
									}
									return retrievedSources{documents: documents, documentKinds: documentKinds, diagnostics: diagnostics, records: records, clarification: &postgres.ProfileClarification{Kind: "ambiguous_entity", Question: "Which matching record did you mean?", Candidates: candidates}}, failures, nil
								}
							}
						}
					}
				}
			} else {
				found, searchErr := pg.Search(ctx, databaseIdentity, password, question, limit, tool)
				add(found, searchErr)
			}
		}
	}
	if active[5] {
		state := "no_matching_query"
		if status, ok := ctx.Value(databaseSelectionStatusKey{}).(string); ok && selection == nil {
			state = status
		}
		if selection != nil {
			state = "no_results"
		}
		count := len(records)
		for _, kind := range documentKinds {
			if kind == "database" {
				count++
			}
		}
		if count > 0 {
			state = "searched"
		}
		if failures > dbFailuresBefore {
			state = "failed"
		}
		diagnostics = append(diagnostics, sourceSearchStatus{Source: "database", Status: state, Results: count})
	}
	return retrievedSources{documents: documents, documentKinds: documentKinds, diagnostics: diagnostics, records: records}, failures, nil
}

func sourceLimits(max int, enabled []bool) []int {
	limits := make([]int, len(enabled))
	active := 0
	for _, value := range enabled {
		if value {
			active++
		}
	}
	if active == 0 || max <= 0 {
		return limits
	}
	target := min(max, active*3)
	base, remainder := target/active, target%active
	for i, value := range enabled {
		if !value {
			continue
		}
		limits[i] = base
		if remainder > 0 {
			limits[i]++
			remainder--
		}
	}
	for i := 0; i < len(limits) && sumSourceLimits(limits) < target; i = (i + 1) % len(limits) {
		if enabled[i] && limits[i] < 3 {
			limits[i]++
		}
	}
	return limits
}

func sumSourceLimits(limits []int) int {
	total := 0
	for _, limit := range limits {
		total += limit
	}
	return total
}

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"iq-kbteams/internal/graph"
	"iq-kbteams/internal/httpx"
)

type sourceToggle struct {
	Enabled bool `json:"enabled"`
}

type sharePointToggle struct {
	Enabled  bool     `json:"enabled"`
	SiteURLs []string `json:"siteUrls"`
}

type sharePointBoundary struct {
	SiteURLs []string `json:"siteUrls"`
}

func sourceEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT COUNT(*) FROM source_boundaries WHERE source_id IN ('user-onedrive','user-sharepoint','user-outlook','user-teams-chats','user-teams-channels','user-postgres') AND enabled=1`).Scan(&enabled)
	return enabled > 0, err
}

func postgresEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT enabled FROM source_boundaries WHERE source_id='user-postgres'`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func teamsChannelsEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT enabled FROM source_boundaries WHERE source_id='user-teams-channels'`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func teamsChatsEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT enabled FROM source_boundaries WHERE source_id='user-teams-chats'`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func outlookEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT enabled FROM source_boundaries WHERE source_id='user-outlook'`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func oneDriveEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT enabled FROM source_boundaries WHERE source_id='user-onedrive'`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func sharePointEnabled(db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRow(`SELECT enabled FROM source_boundaries WHERE source_id='user-sharepoint'`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}

func sharePointSites(db *sql.DB) ([]string, error) {
	var raw []byte
	err := db.QueryRow(`SELECT canonical_boundary FROM source_boundaries WHERE source_id='user-sharepoint'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var boundary sharePointBoundary
	if err := json.Unmarshal(raw, &boundary); err != nil || len(boundary.SiteURLs) > graph.MaxSharePointSites {
		return nil, errors.New("stored SharePoint boundary is invalid")
	}
	return boundary.SiteURLs, nil
}

func sourceHandler(db *sql.DB, postgresConfigured ...bool) http.Handler {
	pgConfigured := len(postgresConfigured) > 0 && postgresConfigured[0]
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/sources", func(w http.ResponseWriter, r *http.Request) {
		enabled, err := oneDriveEnabled(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		sites, err := sharePointSites(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		sharePointActive, err := sharePointEnabled(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		outlookActive, err := outlookEnabled(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		teamsActive, err := teamsChatsEnabled(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		channelsActive, err := teamsChannelsEnabled(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		sources := []map[string]any{
			{"id": "user-onedrive", "kind": "onedrive", "boundary": "me/drive", "enabled": enabled},
			{"id": "user-sharepoint", "kind": "sharepoint", "boundary": "configured-sites", "enabled": sharePointActive, "siteUrls": sites},
			{"id": "user-outlook", "kind": "outlook", "boundary": "me/mailbox", "enabled": outlookActive},
			{"id": "user-teams-chats", "kind": "teams_chats", "boundary": "me/chats", "enabled": teamsActive},
			{"id": "user-teams-channels", "kind": "teams_channels", "boundary": "me/teamwork/associatedTeams/allChannels", "enabled": channelsActive},
		}
		if pgConfigured {
			pgEnabled, err := postgresEnabled(db)
			if err != nil {
				jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
				return
			}
			sources = append(sources, map[string]any{"id": "user-postgres", "kind": "postgres", "boundary": "admin-approved-query-catalog", "enabled": pgEnabled})
		}
		writeJSON(w, http.StatusOK, map[string]any{"sources": sources})
	})
	mux.HandleFunc("PUT /api/admin/sources/onedrive", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		toggle, err := httpx.DecodeOne[sourceToggle](body)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		enabled := 0
		if toggle.Enabled {
			enabled = 1
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-onedrive','onedrive','me/drive',?) ON CONFLICT(source_id) DO UPDATE SET enabled=excluded.enabled`, enabled)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "user-onedrive", "enabled": toggle.Enabled, "updatedAt": time.Now().UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("PUT /api/admin/sources/sharepoint", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		toggle, err := httpx.DecodeOne[sharePointToggle](body)
		if err != nil || len(toggle.SiteURLs) > graph.MaxSharePointSites || (toggle.Enabled && len(toggle.SiteURLs) == 0) {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_sharepoint_configuration"}`)
			return
		}
		canonical := make([]string, 0, len(toggle.SiteURLs))
		seen := make(map[string]struct{}, len(toggle.SiteURLs))
		for _, raw := range toggle.SiteURLs {
			siteURL, err := graph.ValidateSharePointSiteURL(raw)
			if err != nil {
				jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_sharepoint_configuration"}`)
				return
			}
			if _, exists := seen[siteURL]; exists {
				continue
			}
			seen[siteURL] = struct{}{}
			canonical = append(canonical, siteURL)
		}
		encoded, err := json.Marshal(sharePointBoundary{SiteURLs: canonical})
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		enabled := 0
		if toggle.Enabled {
			enabled = 1
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-sharepoint','sharepoint',?,?) ON CONFLICT(source_id) DO UPDATE SET canonical_boundary=excluded.canonical_boundary,enabled=excluded.enabled`, encoded, enabled)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "user-sharepoint", "enabled": toggle.Enabled, "siteUrls": canonical})
	})
	mux.HandleFunc("PUT /api/admin/sources/outlook", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		toggle, err := httpx.DecodeOne[sourceToggle](body)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		enabled := 0
		if toggle.Enabled {
			enabled = 1
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-outlook','outlook','me/mailbox',?) ON CONFLICT(source_id) DO UPDATE SET enabled=excluded.enabled`, enabled)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "user-outlook", "enabled": toggle.Enabled})
	})
	mux.HandleFunc("PUT /api/admin/sources/teams-chats", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		toggle, err := httpx.DecodeOne[sourceToggle](body)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		enabled := 0
		if toggle.Enabled {
			enabled = 1
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-teams-chats','teams_chats','me/chats',?) ON CONFLICT(source_id) DO UPDATE SET enabled=excluded.enabled`, enabled)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "user-teams-chats", "enabled": toggle.Enabled})
	})
	mux.HandleFunc("PUT /api/admin/sources/teams-channels", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		toggle, err := httpx.DecodeOne[sourceToggle](body)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		enabled := 0
		if toggle.Enabled {
			enabled = 1
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-teams-channels','teams_channels','me/teamwork/associatedTeams/allChannels',?) ON CONFLICT(source_id) DO UPDATE SET canonical_boundary=excluded.canonical_boundary,enabled=excluded.enabled`, enabled)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "user-teams-channels", "enabled": toggle.Enabled})
	})
	mux.HandleFunc("PUT /api/admin/sources/postgres", func(w http.ResponseWriter, r *http.Request) {
		if !pgConfigured {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"postgres_not_configured"}`)
			return
		}
		body, err := ioReadRequest(r)
		toggle, decodeErr := httpx.DecodeOne[sourceToggle](body)
		if err != nil || decodeErr != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		enabled := 0
		if toggle.Enabled {
			enabled = 1
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',?) ON CONFLICT(source_id) DO UPDATE SET canonical_boundary=excluded.canonical_boundary,enabled=excluded.enabled`, enabled)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": "user-postgres", "enabled": toggle.Enabled})
	})
	return mux
}

func teamsChatsCheckHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		_, assertion, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		state, err := graph.NewTeamsChats(socketPath).Check(ctx, assertion)
		if err != nil {
			status := http.StatusServiceUnavailable
			if state == "consent_required" {
				status = http.StatusFailedDependency
			} else if state == "permission_denied" {
				status = http.StatusForbidden
			}
			writeJSON(w, status, map[string]string{"status": state})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": state})
	}
}

func teamsChannelsCheckHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		_, assertion, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		state, err := graph.NewTeamsChannels(socketPath).Check(ctx, assertion)
		if err != nil {
			status := http.StatusServiceUnavailable
			if state == "consent_required" {
				status = http.StatusFailedDependency
			} else if state == "permission_denied" {
				status = http.StatusForbidden
			}
			failure := map[string]any{"status": state}
			var detail *graph.ChannelCheckError
			if errors.As(err, &detail) {
				failure["stage"] = detail.Stage
				if detail.HTTPStatus != 0 {
					failure["upstreamStatus"] = detail.HTTPStatus
				}
			}
			writeJSON(w, status, failure)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": state})
	}
}

func outlookCheckHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		_, assertion, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		state, err := graph.NewOutlook(socketPath).Check(ctx, assertion)
		if err != nil {
			status := http.StatusServiceUnavailable
			if state == "consent_required" {
				status = http.StatusFailedDependency
			} else if state == "permission_denied" {
				status = http.StatusForbidden
			} else if state == "not_provisioned" {
				status = http.StatusNotFound
			}
			writeJSON(w, status, map[string]string{"status": state})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": state})
	}
}

func sharePointCheckHandler(socketPath string, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		_, assertion, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		sites, err := sharePointSites(db)
		if err != nil || len(sites) == 0 {
			jsonResponse(w, http.StatusConflict, `{"error":"sharepoint_not_configured"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		for _, site := range sites {
			state, err := graph.NewSharePoint(socketPath).Check(ctx, assertion, site)
			if err != nil {
				status := http.StatusServiceUnavailable
				if state == "consent_required" {
					status = http.StatusFailedDependency
				} else if state == "permission_denied" {
					status = http.StatusForbidden
				} else if state == "not_found" {
					status = http.StatusNotFound
				}
				writeJSON(w, status, map[string]string{"status": state})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "connected", "siteCount": len(sites)})
	}
}

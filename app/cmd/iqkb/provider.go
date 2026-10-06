package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"iq-kbteams/internal/answer"
	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
)

var modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type modelConfig struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"baseUrl,omitempty"`
}

type providerUpdate struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	BaseURL  string `json:"baseUrl,omitempty"`
}

func providerHandler(db *sql.DB, apiKey string, encryptionKey []byte) http.Handler {
	return providerHandlerWithModelAttemptLimit(db, apiKey, encryptionKey, defaultMonthlyModelAttemptLimit)
}

func providerHandlerWithModelAttemptLimit(db *sql.DB, apiKey string, encryptionKey []byte, modelAttemptLimit int) http.Handler {
	return providerHandlerWithControls(db, apiKey, encryptionKey, modelAttemptLimit, newAskAdmissionGate(maxConcurrentAsks, maxConcurrentAsksPerUser))
}

func providerHandlerWithControls(db *sql.DB, apiKey string, encryptionKey []byte, modelAttemptLimit int, admission *askAdmissionGate) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/provider", func(w http.ResponseWriter, r *http.Request) {
		configuration, err := loadModelConfig(db)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]any{"configured": false, "apiKeyConfigured": apiKey != ""})
			return
		}
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":       true,
			"apiKeyConfigured": apiKey != "",
			"provider":         configuration.Provider,
			"model":            configuration.Model,
			"baseUrl":          configuration.BaseURL,
		})
	})
	mux.HandleFunc("PUT /api/admin/provider", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		update, err := httpx.DecodeOne[providerUpdate](body)
		if err != nil || validateProviderUpdate(update) != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_provider_configuration"}`)
			return
		}
		configuration := modelConfig{Provider: update.Provider, Model: update.Model, BaseURL: update.BaseURL}
		encoded, err := json.Marshal(configuration)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, `{"error":"unavailable"}`)
			return
		}
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES('model_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, encoded)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM settings WHERE key='model_test_fingerprint'`)
		}
		if err != nil {
			_ = tx.Rollback()
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if err := tx.Commit(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"configured": true, "provider": configuration.Provider, "model": configuration.Model})
	})
	mux.HandleFunc("POST /api/admin/provider/check", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		configuration, err := loadModelConfig(db)
		if err != nil {
			jsonResponse(w, http.StatusConflict, `{"error":"model_not_configured"}`)
			return
		}
		if apiKey == "" {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_not_configured"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		release, admitted := admission.acquire(strings.ToLower(principal.TenantID + ":" + principal.ObjectID))
		if !admitted {
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"too_many_concurrent_requests"}`)
			return
		}
		defer release()
		reserved, reserveErr := reserveMonthlyModelAttempt(r.Context(), db, modelAttemptLimit)
		if reserveErr != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"model_budget_unavailable"}`)
			return
		}
		if !reserved {
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"monthly_model_limit_reached"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()
		if _, err := answer.Generate(ctx, configuration.Provider, configuration.Model, configuration.BaseURL, apiKey, "Connection check: read [S1] and reply with one short word. [S1] READY"); err != nil {
			jsonResponse(w, http.StatusBadGateway, `{"error":"model_check_failed"}`)
			return
		}
		fingerprint, err := modelFingerprint(db, apiKey, encryptionKey)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if _, err := db.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES('model_test_fingerprint',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, []byte(fingerprint)); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "connected"})
	})
	mux.HandleFunc("DELETE /api/admin/provider", func(w http.ResponseWriter, r *http.Request) {
		tx, err := db.BeginTx(r.Context(), nil)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM settings WHERE key='model_config'`)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM settings WHERE key='model_test_fingerprint'`)
		}
		if err != nil {
			if tx != nil {
				_ = tx.Rollback()
			}
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if err := tx.Commit(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"configured": false})
	})
	return mux
}

func validateProviderUpdate(update providerUpdate) error {
	if !modelNamePattern.MatchString(update.Model) {
		return errors.New("invalid provider fields")
	}
	switch update.Provider {
	case "openai", "anthropic":
		if update.BaseURL != "" {
			return errors.New("base URL is only supported for OpenAI-compatible providers")
		}
	case "openai_compatible":
		parsed, err := url.ParseRequestURI(update.BaseURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(update.BaseURL) > 512 {
			return errors.New("OpenAI-compatible base URL must be an HTTPS origin")
		}
	default:
		return errors.New("unknown model provider")
	}
	return nil
}

func loadModelConfig(db *sql.DB) (modelConfig, error) {
	var encoded []byte
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='model_config'`).Scan(&encoded); err != nil {
		return modelConfig{}, err
	}
	var configuration modelConfig
	if err := json.Unmarshal(encoded, &configuration); err != nil {
		return modelConfig{}, err
	}
	return configuration, nil
}

func modelFingerprint(db *sql.DB, apiKey string, encryptionKey []byte) (string, error) {
	if apiKey == "" {
		return "", errors.New("provider API key is not configured")
	}
	configuration, err := loadModelConfig(db)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return "", err
	}
	hash := hmac.New(sha256.New, encryptionKey)
	_, _ = hash.Write(encoded)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(apiKey))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func modelTested(db *sql.DB, apiKey string, encryptionKey []byte) bool {
	expected, err := modelFingerprint(db, apiKey, encryptionKey)
	if err != nil {
		return false
	}
	var actual []byte
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='model_test_fingerprint'`).Scan(&actual); err != nil {
		return false
	}
	return string(actual) == expected
}

func ioReadRequest(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 {
		return nil, errors.New("request too large or unreadable")
	}
	return body, nil
}

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"iq-kbteams/internal/graph"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
	"iq-kbteams/internal/store"
	"iq-kbteams/internal/web"
	_ "modernc.org/sqlite"
)

type config struct {
	dbPath, bridgeSocket, parserSocket, oboSocket, bridgeKeyFile, encryptionKeyFile string
	tenantID, adminObjectID, appClientID                                            string
	bootstrapSecretFile, postgresDSNFile, modelAPIKeyFile                           string
}

const (
	publicReadTimeout        = 15 * time.Second
	publicWriteTimeout       = 180 * time.Second
	requestProcessingTimeout = 150 * time.Second
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		client := &http.Client{Timeout: 2 * time.Second}
		if readinessCheck(client, "http://127.0.0.1:8080/health/ready") != nil {
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg := config{
		dbPath:              env("SQLITE_PATH", "/var/lib/iqkb/config.sqlite"),
		bridgeSocket:        env("BRIDGE_SOCKET", "/run/iqkb/bridge.sock"),
		parserSocket:        env("PARSER_SOCKET", "/run/parser/parser.sock"),
		oboSocket:           env("OBO_SOCKET", "/run/iqkb/obo.sock"),
		bridgeKeyFile:       os.Getenv("BRIDGE_HMAC_KEY_FILE"),
		encryptionKeyFile:   os.Getenv("APP_ENCRYPTION_KEY_FILE"),
		tenantID:            os.Getenv("TENANT_ID"),
		adminObjectID:       os.Getenv("ADMIN_OBJECT_ID"),
		appClientID:         os.Getenv("APP_CLIENT_ID"),
		bootstrapSecretFile: os.Getenv("BOOTSTRAP_SECRET_FILE"),
		postgresDSNFile:     os.Getenv("POSTGRES_DSN_FILE"),
		modelAPIKeyFile:     os.Getenv("MODEL_API_KEY_FILE"),
	}
	if err := run(cfg); err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func readinessCheck(client *http.Client, endpoint string) error {
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness returned HTTP %d", response.StatusCode)
	}
	var state struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&state); err != nil {
		return err
	}
	if state.Status != "ready" {
		return errors.New("application is not ready")
	}
	return nil
}

func run(cfg config) error {
	modelAttemptLimit, err := configuredMonthlyModelAttemptLimit()
	if err != nil {
		return err
	}
	auditRetentionDays, err := configuredAuditRetentionDays()
	if err != nil {
		return err
	}
	modelAPIKey, err := readSecret(cfg.modelAPIKeyFile, "MODEL_API_KEY")
	if err != nil {
		return fmt.Errorf("provider API key: %w", err)
	}
	bootstrapSecret, err := readSecret(cfg.bootstrapSecretFile, "BOOTSTRAP_SECRET")
	if err != nil {
		return fmt.Errorf("bootstrap secret: %w", err)
	}
	encryptionKey, err := readKey(cfg.encryptionKeyFile, "APP_ENCRYPTION_KEY")
	if err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.dbPath), 0700); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+cfg.dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return err
	}
	if err := store.Migrate(db); err != nil {
		return err
	}
	if err := pruneExpiredAuditEvents(context.Background(), db, auditRetentionDays); err != nil {
		return fmt.Errorf("clean expired audit events: %w", err)
	}
	if err := checkPersistedKey(db, encryptionKey); err != nil {
		return err
	}
	var pg *postgres.Connector
	dsn, err := readSecret(cfg.postgresDSNFile, "POSTGRES_DSN")
	if err != nil {
		return fmt.Errorf("PostgreSQL connection secret: %w", err)
	}
	if dsn != "" {
		pg, err = postgres.Open(context.Background(), dsn)
		if err != nil {
			return err
		}
		defer pg.Close()
	}
	if err := store.SeedAdmin(db, cfg.tenantID, cfg.adminObjectID); err != nil {
		return err
	}
	baseVerifier, err := identity.NewVerifier(cfg.tenantID, cfg.appClientID, cfg.appClientID)
	if err != nil {
		return err
	}
	var verifier tokenVerifier = directoryTokenVerifier{base: baseVerifier, db: db, socket: cfg.oboSocket}
	if err := os.MkdirAll(filepath.Dir(cfg.bridgeSocket), 0700); err != nil {
		return err
	}
	_ = os.Remove(cfg.bridgeSocket)
	bridge, err := net.Listen("unix", cfg.bridgeSocket)
	if err != nil {
		return fmt.Errorf("listen internal socket: %w", err)
	}
	if err := os.Chmod(cfg.bridgeSocket, 0600); err != nil {
		_ = bridge.Close()
		return err
	}
	internalMux := http.NewServeMux()
	internalMux.HandleFunc("POST /internal/v1/activities", unavailable)
	internalMux.HandleFunc("POST /internal/v1/tokens", unavailable)
	internalMux.HandleFunc("POST /internal/v1/parse", parserHandler(cfg.parserSocket))
	bridgeKey, err := readKey(cfg.bridgeKeyFile, "BRIDGE_HMAC_KEY")
	if err != nil {
		return fmt.Errorf("bridge key: %w", err)
	}
	internalServer := &http.Server{Handler: authenticateBridge(bridgeKey, db, internalMux), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := internalServer.Serve(bridge); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("internal server stopped", "error", err)
		}
	}()

	modelAdmission := newAskAdmissionGate(maxConcurrentAsks, maxConcurrentAsksPerUser)
	askRateLimit := newAskRateGate()
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { jsonResponse(w, http.StatusOK, `{"status":"ok"}`) })
	publicMux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"status":"not_ready"}`)
			return
		}
		jsonResponse(w, http.StatusOK, `{"status":"ready"}`)
	})
	publicMux.Handle("/", web.Handler())
	publicMux.Handle("GET /api/session", authenticate(verifier, db, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sessionHandler(db, w, r) })))
	publicMux.Handle("POST /api/ask", authenticateAsk(verifier, db, askRateLimit, askHandlerWithControls(db, encryptionKey, cfg.oboSocket, cfg.parserSocket, pg, modelAPIKey, modelAttemptLimit, modelAdmission)))
	publicMux.Handle("/api/setup/", authenticate(verifier, db, true, setupHandler(db, encryptionKey, bootstrapSecret, cfg.oboSocket, pg, modelAPIKey)))
	publicMux.Handle("POST /api/admin/checks/onedrive", authenticate(verifier, db, true, http.HandlerFunc(oneDriveCheckHandler(cfg.oboSocket))))
	publicMux.Handle("POST /api/admin/checks/sharepoint", authenticate(verifier, db, true, http.HandlerFunc(sharePointCheckHandler(cfg.oboSocket, db))))
	publicMux.Handle("POST /api/admin/checks/outlook", authenticate(verifier, db, true, http.HandlerFunc(outlookCheckHandler(cfg.oboSocket))))
	publicMux.Handle("POST /api/admin/checks/teams-chats", authenticate(verifier, db, true, http.HandlerFunc(teamsChatsCheckHandler(cfg.oboSocket))))
	publicMux.Handle("POST /api/admin/checks/teams-channels", authenticate(verifier, db, true, http.HandlerFunc(teamsChannelsCheckHandler(cfg.oboSocket))))
	providerRoutes := authenticate(verifier, db, true, providerHandlerWithControls(db, modelAPIKey, encryptionKey, modelAttemptLimit, modelAdmission))
	publicMux.Handle("/api/admin/provider", providerRoutes)
	publicMux.Handle("/api/admin/provider/", providerRoutes)
	sourceRoutes := authenticate(verifier, db, true, sourceHandler(db, pg != nil))
	publicMux.Handle("/api/admin/sources", sourceRoutes)
	publicMux.Handle("/api/admin/sources/", sourceRoutes)
	postgresRoutes := authenticate(verifier, db, true, postgresHandler(db, encryptionKey, pg))
	publicMux.Handle("/api/admin/postgres/auth", authenticate(verifier, db, true, postgresAuthHandler(db, encryptionKey, pg)))
	publicMux.Handle("/api/admin/postgres/auth/", authenticate(verifier, db, true, postgresAuthHandler(db, encryptionKey, pg)))
	publicMux.Handle("/api/admin/postgres/", postgresRoutes)
	publicMux.Handle("/api/admin/postgres/profile-tests", postgresRoutes)
	publicMux.Handle("/api/postgres/profiles", authenticate(verifier, db, false, postgresProfilesHandler(db, encryptionKey, pg)))
	publicMux.Handle("/api/postgres/profiles/", authenticate(verifier, db, false, postgresProfileTestHandler(db, encryptionKey, pg)))
	publicMux.Handle("POST /api/admin/checks/postgres", authenticate(verifier, db, true, postgresCheckHandler(db, encryptionKey, pg)))
	publicMux.Handle("/api/postgres/credentials", authenticate(verifier, db, false, postgresCredentialHandler(db, encryptionKey, pg)))
	publicMux.Handle("/api/admin/", authenticate(verifier, db, true, http.HandlerFunc(unavailable)))
	publicServer := newPublicHTTPServer(limitBody(publicMux))
	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	retentionWorkerDone := startAuditRetentionWorker(shutdownSignal, db, auditRetentionDays)
	defer func() {
		stop()
		<-retentionWorkerDone
	}()
	serveError := make(chan error, 1)
	go func() { serveError <- publicServer.ListenAndServe() }()
	select {
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownSignal.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		publicErr := publicServer.Shutdown(shutdownCtx)
		if publicErr != nil {
			_ = publicServer.Close()
		}
		internalErr := internalServer.Shutdown(shutdownCtx)
		if internalErr != nil {
			_ = internalServer.Close()
		}
		return errors.Join(publicErr, internalErr)
	}
}

func newPublicHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              env("HTTP_LISTEN_ADDR", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       publicReadTimeout,
		WriteTimeout:      publicWriteTimeout,
		IdleTimeout:       60 * time.Second,
	}
}

func encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, errors.New("AES-256 key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func checkPersistedKey(db *sql.DB, key []byte) error {
	var blob []byte
	err := db.QueryRow(`SELECT value FROM settings WHERE key='encryption_key_check'`).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		nonce, ciphertext, err := encrypt(key, []byte("iq-kbteams-key-check-v1"))
		if err != nil {
			return err
		}
		_, err = db.Exec(`INSERT INTO settings(key, value) VALUES ('encryption_key_check', ?)`, append(nonce, ciphertext...))
		return err
	}
	if err != nil {
		return err
	}
	if len(blob) < 12 {
		return errors.New("stored encryption key check is invalid")
	}
	plain, err := decrypt(key, blob[:12], blob[12:])
	if err != nil || string(plain) != "iq-kbteams-key-check-v1" {
		return errors.New("configured encryption key cannot decrypt existing app data")
	}
	return nil
}

func readKey(path, variable string) ([]byte, error) {
	var b []byte
	if strings.TrimSpace(path) != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		b = contents
	} else {
		b = []byte(os.Getenv(variable))
	}
	if len(b) != 32 {
		b = []byte(strings.TrimSpace(string(b)))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s or %s is required", variable, variable+"_FILE")
	}
	if len(b) == 64 {
		decoded := make([]byte, hex.DecodedLen(len(b)))
		if _, err := hex.Decode(decoded, b); err == nil {
			b = decoded
		}
	}
	if len(b) != 32 {
		return nil, errors.New("key file must contain 32 raw bytes or 64 hex characters")
	}
	return b, nil
}

func readSecret(path, variable string) (string, error) {
	var value []byte
	if strings.TrimSpace(path) != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		value = contents
	} else {
		value = []byte(os.Getenv(variable))
	}
	secret := strings.TrimSpace(string(value))
	if secret == "" {
		return "", nil
	}
	if len(secret) < 8 || len(secret) > 4096 || strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("secret must contain 8 to 4096 non-whitespace characters")
	}
	return secret, nil
}

func authenticateBridge(key []byte, db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 34<<20)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		ts, nonce, sig := r.Header.Get("X-IQ-Timestamp"), r.Header.Get("X-IQ-Nonce"), r.Header.Get("X-IQ-Signature")
		sec, err := strconv.ParseInt(ts, 10, 64)
		now := time.Now()
		if err != nil || r.URL.RawQuery != "" || len(nonce) != 48 || len(sig) != 64 || time.Unix(sec, 0).Before(now.Add(-60*time.Second)) || time.Unix(sec, 0).After(now.Add(30*time.Second)) {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		if _, err := hex.DecodeString(nonce); err != nil {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		digest := sha256.Sum256(body)
		canonical := r.Method + "\n" + r.URL.Path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
		mac := hmac.New(sha256.New, key)
		_, _ = io.WriteString(mac, canonical)
		expected := mac.Sum(nil)
		provided, err := hex.DecodeString(sig)
		if err != nil || len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		if _, err := db.ExecContext(r.Context(), `DELETE FROM bridge_nonces WHERE expires_at <= ?`, now.Unix()); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		result, err := db.ExecContext(r.Context(), `INSERT OR IGNORE INTO bridge_nonces(nonce, expires_at) VALUES (?, ?)`, nonce, now.Add(120*time.Second).Unix())
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		inserted, err := result.RowsAffected()
		if err != nil || inserted != 1 {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func parserHandler(socketPath string) http.HandlerFunc {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 34<<20))
		if err != nil {
			jsonResponse(w, http.StatusRequestEntityTooLarge, `{"error":"input_size_limit"}`)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://parser/v1/parse", bytes.NewReader(body))
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"parser_unavailable"}`)
			return
		}
		defer response.Body.Close()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, io.LimitReader(response.Body, 3<<20)); err != nil {
			return
		}
	}
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

func unavailable(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
		return
	default:
	}
	jsonResponse(w, http.StatusServiceUnavailable, `{"error":"not_configured"}`)
}

func oneDriveCheckHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
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
		state, err := graph.NewOneDrive(socketPath).Check(ctx, assertion)
		if err != nil {
			switch state {
			case "consent_required":
				writeJSON(w, http.StatusFailedDependency, map[string]string{"status": state})
			case "permission_denied":
				writeJSON(w, http.StatusForbidden, map[string]string{"status": state})
			case "not_provisioned":
				writeJSON(w, http.StatusNotFound, map[string]string{"status": state})
			default:
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": state})
	}
}

type identityContextKey struct{}
type roleContextKey struct{}

type tokenVerifier interface {
	Verify(context.Context, string) (identity.Principal, error)
}

func authenticate(verifier tokenVerifier, db *sql.DB, adminOnly bool, next http.Handler) http.Handler {
	return authenticateWithAskRateLimit(verifier, db, adminOnly, nil, next)
}

func authenticateAsk(verifier tokenVerifier, db *sql.DB, gate *askRateGate, next http.Handler) http.Handler {
	return authenticateWithAskRateLimit(verifier, db, false, gate, next)
}

func authenticateWithAskRateLimit(verifier tokenVerifier, db *sql.DB, adminOnly bool, gate *askRateGate, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Get("Authorization")) > 8192 {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" || strings.ContainsAny(raw, " \t\r\n") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="iq-kbteams"`)
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		principal, err := verifier.Verify(ctx, raw)
		if err != nil {
			if errors.Is(err, identity.ErrMetadataUnavailable) {
				jsonResponse(w, http.StatusServiceUnavailable, `{"error":"identity_unavailable"}`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="iq-kbteams", error="invalid_token"`)
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		if gate != nil {
			if allowed, retryAfter := gate.allow(strings.ToLower(principal.TenantID+":"+principal.ObjectID), time.Now()); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				jsonResponse(w, http.StatusTooManyRequests, `{"error":"rate_limited"}`)
				return
			}
		}
		role := "User"
		var assigned int
		err = db.QueryRowContext(ctx, `SELECT 1 FROM admin_assignments WHERE tenant_id=? AND object_id=?`, principal.TenantID, principal.ObjectID).Scan(&assigned)
		if err == nil {
			role = "Admin"
		} else if !errors.Is(err, sql.ErrNoRows) {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if adminOnly && role != "Admin" {
			jsonResponse(w, http.StatusForbidden, `{"error":"forbidden"}`)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), identityContextKey{}, principal))
		r = r.WithContext(context.WithValue(r.Context(), roleContextKey{}, role))
		next.ServeHTTP(w, r)
	})
}

func sessionHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(identityContextKey{}).(identity.Principal)
	role := r.Context().Value(roleContextKey{}).(string)
	var active []byte
	if err := db.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key='setup_activated'`).Scan(&active); err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"tenantId": principal.TenantID, "objectId": principal.ObjectID, "role": role, "active": string(active) == "1"})
}

func setupHandler(db *sql.DB, encryptionKey []byte, bootstrapSecret, oboSocket string, pg *postgres.Connector, apiKey string) http.Handler {
	return setupHandlerWithCheck(db, bootstrapSecret, apiKey, encryptionKey, func(ctx context.Context, assertion string, principal identity.Principal) (string, error) {
		return checkEnabledSourceAccess(ctx, db, encryptionKey, assertion, oboSocket, pg, principal)
	})
}

func setupHandlerWithCheck(db *sql.DB, bootstrapSecret, apiKey string, encryptionKey []byte, checkSources func(context.Context, string, identity.Principal) (string, error)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/setup/status", func(w http.ResponseWriter, r *http.Request) {
		var active []byte
		if err := db.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key='setup_activated'`).Scan(&active); err != nil && !errors.Is(err, sql.ErrNoRows) {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		ready, err := setupReady(db, apiKey, encryptionKey)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": string(active) == "1", "wizardReady": ready})
	})
	mux.HandleFunc("POST /api/setup/activate", func(w http.ResponseWriter, r *http.Request) {
		var activated []byte
		if err := db.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key='setup_activated'`).Scan(&activated); err == nil && string(activated) == "1" {
			jsonResponse(w, http.StatusConflict, `{"error":"already_activated"}`)
			return
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		provided := []byte(r.Header.Get("X-Setup-Secret"))
		configured := []byte(bootstrapSecret)
		if len(provided) == 0 || len(configured) == 0 || len(provided) != len(configured) || subtle.ConstantTimeCompare(provided, configured) != 1 {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ready, err := setupReady(db, apiKey, encryptionKey)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		if !ready {
			jsonResponse(w, http.StatusConflict, `{"error":"setup_incomplete"}`)
			return
		}
		_, assertion, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok {
			jsonResponse(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		state, err := checkSources(ctx, assertion, principal)
		if err != nil {
			status := http.StatusFailedDependency
			if state == "permission_denied" {
				status = http.StatusForbidden
			} else if state == "not_provisioned" || state == "not_found" {
				status = http.StatusNotFound
			}
			failure := map[string]string{"error": "source_check_failed", "status": state}
			var sourceErr *sourceAccessError
			if errors.As(err, &sourceErr) {
				failure["source"] = sourceErr.source
			}
			slog.Warn("workspace source access check failed", "source", failure["source"], "status", state)
			writeJSON(w, status, failure)
			return
		}
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		enabled, err := sourceEnabledTx(ctx, tx)
		modelOK := err == nil && enabled && modelTestedTx(ctx, tx, apiKey, encryptionKey)
		if modelOK {
			_, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('setup_activated',x'31') ON CONFLICT(key) DO UPDATE SET value=x'31'`)
		}
		if err == nil && modelOK {
			_, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('setup_activated_by',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, []byte(principal.TenantID+":"+principal.ObjectID))
		}
		if err == nil && modelOK {
			_, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('setup_activated_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, []byte(time.Now().UTC().Format(time.RFC3339)))
		}
		if err != nil || !modelOK {
			_ = tx.Rollback()
			jsonResponse(w, http.StatusConflict, `{"error":"setup_incomplete"}`)
			return
		}
		if err := tx.Commit(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": true})
	})
	return mux
}

func setupReady(db *sql.DB, apiKey string, encryptionKey []byte) (bool, error) {
	enabled, err := sourceEnabled(db)
	if err != nil {
		return false, err
	}
	return enabled && modelTested(db, apiKey, encryptionKey), nil
}

type sourceAccessError struct {
	source string
	cause  error
}

func (e *sourceAccessError) Error() string { return e.source + " source check failed" }
func (e *sourceAccessError) Unwrap() error { return e.cause }
func sourceAccessFailure(source, state string, err error) (string, error) {
	return state, &sourceAccessError{source: source, cause: err}
}

func checkEnabledSourceAccess(ctx context.Context, db *sql.DB, encryptionKey []byte, assertion, socketPath string, pg *postgres.Connector, principal identity.Principal) (string, error) {
	oneDrive, err := oneDriveEnabled(db)
	if err != nil {
		return "unavailable", err
	}
	var sharePointEnabled int
	err = db.QueryRowContext(ctx, `SELECT enabled FROM source_boundaries WHERE source_id='user-sharepoint'`).Scan(&sharePointEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		sharePointEnabled = 0
	} else if err != nil {
		return "unavailable", err
	}
	outlook, err := outlookEnabled(db)
	if err != nil {
		return "unavailable", err
	}
	teamsChats, err := teamsChatsEnabled(db)
	if err != nil {
		return "unavailable", err
	}
	teamsChannels, err := teamsChannelsEnabled(db)
	if err != nil {
		return "unavailable", err
	}
	postgresActive, err := postgresEnabled(db)
	if err != nil {
		return "unavailable", err
	}
	if !oneDrive && sharePointEnabled == 0 && !outlook && !teamsChats && !teamsChannels && !postgresActive {
		return "no_sources_enabled", errors.New("no sources are enabled")
	}
	if oneDrive {
		state, err := graph.NewOneDrive(socketPath).Check(ctx, assertion)
		if err != nil {
			return sourceAccessFailure("onedrive", state, err)
		}
	}
	if sharePointEnabled == 1 {
		sites, err := sharePointSites(db)
		if err != nil || len(sites) == 0 {
			return sourceAccessFailure("sharepoint", "invalid_site", errors.New("SharePoint source has no configured sites"))
		}
		connector := graph.NewSharePoint(socketPath)
		for _, site := range sites {
			state, err := connector.Check(ctx, assertion, site)
			if err != nil {
				return sourceAccessFailure("sharepoint", state, err)
			}
		}
	}
	if outlook {
		state, err := graph.NewOutlook(socketPath).Check(ctx, assertion)
		if err != nil {
			return sourceAccessFailure("outlook", state, err)
		}
	}
	if teamsChats {
		state, err := graph.NewTeamsChats(socketPath).Check(ctx, assertion)
		if err != nil {
			return sourceAccessFailure("teams-chats", state, err)
		}
	}
	if teamsChannels {
		state, err := graph.NewTeamsChannels(socketPath).Check(ctx, assertion)
		if err != nil {
			return sourceAccessFailure("teams-channels", state, err)
		}
	}
	if postgresActive {
		if pg == nil {
			return sourceAccessFailure("postgres", "postgres_not_configured", errors.New("PostgreSQL is not configured"))
		}
		if principal.VerifiedEmail == "" {
			return sourceAccessFailure("postgres", "postgres_verified_email_required", errors.New("verified organizational email is required"))
		}
		pg, databaseIdentity, password, err := postgresAccess(ctx, db, encryptionKey, pg, principal)
		if err != nil {
			return sourceAccessFailure("postgres", "postgres_credentials_required", err)
		}
		if err := pg.CheckIdentity(ctx, databaseIdentity, password); err != nil {
			return sourceAccessFailure("postgres", "permission_denied", err)
		}
		tools, err := postgres.Catalog(db)
		if err != nil || len(tools) == 0 {
			return sourceAccessFailure("postgres", "approved_query_required", errors.New("an approved PostgreSQL query is required"))
		}
		if !postgresProfilesReady(ctx, db, pg, principal.TenantID, tools) {
			return sourceAccessFailure("postgres", "second_user_test_required", errors.New("each PostgreSQL profile requires tests from two distinct mapped users"))
		}
		for _, tool := range tools {
			if err := checkPostgresTool(ctx, pg, databaseIdentity, password, tool); err != nil {
				return sourceAccessFailure("postgres", "approved_query_failed", errors.New("an approved PostgreSQL query could not be executed"))
			}
		}
	}
	return "connected", nil
}

func postgresProfilesActivationReady(db *sql.DB, tenantID string, tools []postgres.QueryTool) bool {
	for _, tool := range tools {
		if len(tool.ProfileConfig) == 0 || string(tool.ProfileConfig) == "{}" {
			continue
		}
		var profile postgres.BusinessProfile
		if json.Unmarshal(tool.ProfileConfig, &profile) != nil {
			return false
		}
		fingerprint, err := postgres.ProfileFingerprint(profile)
		if err != nil {
			return false
		}
		var tested int
		err = db.QueryRow(`SELECT COUNT(DISTINCT t.database_identity) FROM postgres_profile_tests t JOIN identity_bindings b ON b.tenant_id=t.tenant_id AND b.object_id=t.object_id AND b.database_identity=t.database_identity JOIN encrypted_secrets s ON s.secret_id='postgres_password:'||t.tenant_id||':'||t.object_id WHERE t.tenant_id=? AND t.tool_id=? AND t.profile_version=? AND t.schema_fingerprint=? AND t.profile_generation=? AND t.binding_email=b.verified_email AND t.binding_reviewed_at=b.reviewed_at AND t.credential_generation=s.updated_at AND t.outcome='passed' AND (SELECT COUNT(*) FROM identity_bindings b2 WHERE b2.tenant_id=b.tenant_id AND b2.database_identity=b.database_identity)=1`, strings.ToLower(tenantID), tool.ID, tool.Version, fingerprint, fingerprint).Scan(&tested)
		if err != nil || tested < 2 {
			return false
		}
	}
	return true
}

func sourceEnabledTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	var enabled int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM source_boundaries WHERE source_id IN ('user-onedrive','user-sharepoint','user-outlook','user-teams-chats','user-teams-channels','user-postgres') AND enabled=1`).Scan(&enabled)
	return enabled > 0, err
}

func modelTestedTx(ctx context.Context, tx *sql.Tx, apiKey string, encryptionKey []byte) bool {
	var encoded, fingerprint []byte
	if err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='model_config'`).Scan(&encoded); err != nil {
		return false
	}
	if apiKey == "" {
		return false
	}
	if err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='model_test_fingerprint'`).Scan(&fingerprint); err != nil {
		return false
	}
	var configuration modelConfig
	if err := json.Unmarshal(encoded, &configuration); err != nil {
		return false
	}
	canonical, err := json.Marshal(configuration)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, encryptionKey)
	_, _ = mac.Write(canonical)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(apiKey))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(mac.Sum(nil))), fingerprint) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func jsonResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

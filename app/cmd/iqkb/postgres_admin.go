package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

var objectIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$`)

type postgresIdentityInput struct {
	ObjectID         string `json:"objectId"`
	VerifiedEmail    string `json:"verifiedEmail"`
	DatabaseIdentity string `json:"databaseIdentity"`
}

type postgresIdentity struct {
	ObjectID         string `json:"objectId"`
	VerifiedEmail    string `json:"verifiedEmail"`
	DatabaseIdentity string `json:"databaseIdentity"`
	ReviewedBy       string `json:"reviewedBy"`
	ReviewedAt       string `json:"reviewedAt"`
}

type postgresCredentialInput struct {
	Password string `json:"password"`
}

var (
	errProfileCatalogUnavailable  = errors.New("profile catalog unavailable")
	errProfilePostgresUnavailable = errors.New("PostgreSQL unavailable")
	errProfileCredentialsRequired = errors.New("admin credentials required")
	errProfileSchemaCheckFailed   = errors.New("profile schema check failed")
	errInvalidBusinessProfile     = errors.New("invalid business profile")
)

func prepareBusinessProfile(ctx context.Context, db *sql.DB, encryptionKey []byte, pg *postgres.Connector, principal identity.Principal, profile postgres.BusinessProfile) (postgres.QueryTool, error) {
	var current int
	err := db.QueryRowContext(ctx, `SELECT version FROM query_tools WHERE tool_id=?`, profile.ID).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return postgres.QueryTool{}, errProfileCatalogUnavailable
	}
	profile.Version = 1
	if err == nil {
		profile.Version = current + 1
	}
	profile.SchemaFingerprint = ""
	if pg == nil {
		return postgres.QueryTool{}, errProfilePostgresUnavailable
	}
	pg, login, password, err := postgresAccess(ctx, db, encryptionKey, pg, principal)
	if err != nil {
		return postgres.QueryTool{}, errProfileCredentialsRequired
	}
	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	if profile.Relationship != nil {
		if err := resolveRelatedParentProfile(checkCtx, db, pg, login, password, &profile); err != nil {
			cancel()
			return postgres.QueryTool{}, errInvalidBusinessProfile
		}
	}
	fingerprint, err := pg.ProfileSchemaFingerprint(checkCtx, login, password, profile)
	cancel()
	if err != nil {
		return postgres.QueryTool{}, errProfileSchemaCheckFailed
	}
	profile.SchemaFingerprint = fingerprint
	query, err := postgres.CompileBusinessProfile(profile)
	if err != nil {
		return postgres.QueryTool{}, errInvalidBusinessProfile
	}
	parameters := postgres.ProfileParameters(profile)
	outputs := postgres.ProfileOutputColumns(profile)
	config, err := json.Marshal(profile)
	if err != nil || len(config) > 32<<10 {
		return postgres.QueryTool{}, errInvalidBusinessProfile
	}
	approval := strings.TrimSpace(profile.Approval) + "; reviewed-by=" + principal.TenantID + ":" + principal.ObjectID
	if len(approval) > 256 {
		return postgres.QueryTool{}, errInvalidBusinessProfile
	}
	tool := postgres.QueryTool{ID: profile.ID, Version: profile.Version, Description: profile.Label, SQL: query, Parameters: parameters, OutputColumns: outputs, ApprovalRecord: approval, ProfileConfig: config}
	if postgres.ValidateQueryTool(tool) != nil {
		return postgres.QueryTool{}, errInvalidBusinessProfile
	}
	return tool, nil
}

func resolveRelatedParentProfile(ctx context.Context, db *sql.DB, pg *postgres.Connector, login, password string, profile *postgres.BusinessProfile) error {
	if profile.Relationship.ParentProfileID == profile.ID {
		return errors.New("related profile cannot reference itself")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT profile_config FROM query_tools WHERE tool_id=?`, profile.Relationship.ParentProfileID).Scan(&raw); err != nil {
		return errors.New("related parent profile does not exist")
	}
	var parent postgres.BusinessProfile
	if json.Unmarshal(raw, &parent) != nil || parent.ID != profile.Relationship.ParentProfileID || postgres.ValidateBusinessProfile(parent) != nil || parent.Capability != "entity_lookup" || parent.SchemaFingerprint == "" {
		return errors.New("related parent must be a saved entity lookup profile")
	}
	fingerprint, err := pg.ProfileSchemaFingerprint(ctx, login, password, parent)
	if err != nil || fingerprint != parent.SchemaFingerprint {
		return errors.New("related parent profile is stale or inaccessible")
	}
	profile.Relationship.ParentSchema = parent.Schema
	profile.Relationship.ParentRelation = parent.Relation
	profile.Relationship.ParentKeyColumn = parent.KeyColumn
	profile.Relationship.ParentLabelColumn = parent.LabelColumn
	profile.Relationship.ParentSearchColumns = append([]string(nil), parent.SearchColumns...)
	parentKeyType, err := pg.ProfileColumnType(ctx, login, password, parent.Schema, parent.Relation, parent.KeyColumn)
	if err != nil {
		return errors.New("related parent key is unavailable or unsupported")
	}
	profile.Relationship.ParentKeyType = parentKeyType
	typ, err := pg.ProfileColumnType(ctx, login, password, profile.Schema, profile.Relation, profile.Relationship.ChildForeignKey)
	if err != nil {
		return errors.New("related child key is unavailable or unsupported")
	}
	profile.Relationship.ChildForeignKeyType = typ
	return nil
}

func profilePreparationStatus(err error) int {
	switch err {
	case errProfileCredentialsRequired:
		return http.StatusConflict
	case errProfilePostgresUnavailable:
		return http.StatusServiceUnavailable
	case errProfileSchemaCheckFailed:
		return http.StatusFailedDependency
	case errProfileCatalogUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func profilePreparationErrorCode(err error) string {
	switch err {
	case errProfilePostgresUnavailable:
		return "postgres_not_configured"
	case errProfileCredentialsRequired:
		return "administrator_credentials_required"
	case errProfileSchemaCheckFailed:
		return "profile_schema_check_failed"
	case errProfileCatalogUnavailable:
		return "query_catalog_unavailable"
	default:
		return "invalid_business_profile"
	}
}

func postgresHandler(db *sql.DB, encryptionKey []byte, pg *postgres.Connector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/postgres/discovery", func(w http.ResponseWriter, r *http.Request) {
		if pg == nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"postgres_not_configured"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		pg, login, password, err := postgresAccess(r.Context(), db, encryptionKey, pg, principal)
		if err != nil {
			jsonResponse(w, http.StatusConflict, `{"error":"administrator_credentials_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		page, err := pg.Discover(ctx, login, password, r.URL.Query().Get("afterSchema"), r.URL.Query().Get("afterName"))
		if err != nil {
			jsonResponse(w, http.StatusFailedDependency, `{"error":"metadata_discovery_failed"}`)
			return
		}
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("GET /api/admin/postgres/status", func(w http.ResponseWriter, _ *http.Request) {
		count := 0
		tools, err := postgres.Catalog(db)
		if err == nil {
			count = len(tools)
		}
		writeJSON(w, http.StatusOK, map[string]any{"configured": pg != nil, "queryCount": count, "credentialMode": func() string {
			if pg.SharedCredentialsConfigured() {
				return "shared-adapter"
			}
			return "per-user-password"
		}()})
	})
	mux.HandleFunc("GET /api/admin/postgres/profile-tests", func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		query := `SELECT tool_id,profile_version,object_id,database_identity,tested_at,outcome,error_category FROM postgres_profile_tests WHERE tenant_id=? ORDER BY tool_id,object_id`
		if pg.SharedCredentialsConfigured() {
			query = `SELECT t.tool_id,q.version,t.object_id,t.database_role,t.tested_at,t.outcome,'' FROM postgres_adapter_profile_tests t JOIN query_tools q ON q.tool_id=t.tool_id WHERE t.tenant_id=? ORDER BY t.tool_id,t.object_id`
		}
		rows, err := db.QueryContext(r.Context(), query, strings.ToLower(principal.TenantID))
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"profile_tests_unavailable"}`)
			return
		}
		defer rows.Close()
		tests := make([]map[string]any, 0)
		for rows.Next() {
			var id, object, login, at, outcome, category string
			var version int
			if err := rows.Scan(&id, &version, &object, &login, &at, &outcome, &category); err != nil {
				jsonResponse(w, http.StatusServiceUnavailable, `{"error":"profile_tests_unavailable"}`)
				return
			}
			tests = append(tests, map[string]any{"profileId": id, "version": version, "objectId": object, "databaseIdentity": login, "testedAt": at, "status": outcome, "category": category})
		}
		if err := rows.Err(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"profile_tests_unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tests": tests})
	})
	mux.HandleFunc("GET /api/admin/postgres/identities", func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		rows, err := db.QueryContext(r.Context(), `SELECT object_id,verified_email,database_identity,reviewed_by,reviewed_at FROM identity_bindings WHERE tenant_id=? ORDER BY object_id`, principal.TenantID)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		defer rows.Close()
		bindings := make([]postgresIdentity, 0)
		for rows.Next() {
			var binding postgresIdentity
			if err := rows.Scan(&binding.ObjectID, &binding.VerifiedEmail, &binding.DatabaseIdentity, &binding.ReviewedBy, &binding.ReviewedAt); err != nil {
				jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
				return
			}
			bindings = append(bindings, binding)
		}
		if err := rows.Err(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"identities": bindings})
	})
	mux.HandleFunc("PUT /api/admin/postgres/identities", func(w http.ResponseWriter, r *http.Request) {
		if pg == nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"postgres_not_configured"}`)
			return
		}
		body, err := ioReadRequest(r)
		input, decodeErr := httpx.DecodeOne[postgresIdentityInput](body)
		input.VerifiedEmail = strings.ToLower(strings.TrimSpace(input.VerifiedEmail))
		if err != nil || decodeErr != nil || !objectIDPattern.MatchString(input.ObjectID) || !validVerifiedEmail(input.VerifiedEmail) || !postgres.ValidDatabaseIdentity(input.DatabaseIdentity) {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_identity_mapping"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		now := time.Now().UTC().Format(time.RFC3339)
		tx, err := db.BeginTx(r.Context(), nil)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_login_claims WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), strings.ToLower(input.ObjectID))
		}
		if err == nil {
			var duplicate int
			err = tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM identity_bindings WHERE tenant_id=? AND database_identity=? AND object_id<>?`, strings.ToLower(principal.TenantID), input.DatabaseIdentity, strings.ToLower(input.ObjectID)).Scan(&duplicate)
			if err == nil && duplicate != 0 {
				err = errors.New("database login is already mapped")
			}
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO postgres_login_claims(tenant_id,database_identity,object_id) VALUES(?,?,?)`, strings.ToLower(principal.TenantID), input.DatabaseIdentity, strings.ToLower(input.ObjectID))
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM encrypted_secrets WHERE secret_id=?`, postgresSecretID(principal.TenantID, input.ObjectID))
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at)
VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,object_id) DO UPDATE SET verified_email=excluded.verified_email,database_identity=excluded.database_identity,reviewed_by=excluded.reviewed_by,reviewed_at=excluded.reviewed_at`, strings.ToLower(principal.TenantID), strings.ToLower(input.ObjectID), input.VerifiedEmail, input.DatabaseIdentity, principal.TenantID+":"+principal.ObjectID, now)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_profile_tests WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), strings.ToLower(input.ObjectID))
		}
		if err != nil {
			if tx != nil {
				_ = tx.Rollback()
			}
			jsonResponse(w, http.StatusConflict, `{"error":"identity_mapping_conflict"}`)
			return
		}
		if err := tx.Commit(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, postgresIdentity{ObjectID: strings.ToLower(input.ObjectID), VerifiedEmail: input.VerifiedEmail, DatabaseIdentity: input.DatabaseIdentity, ReviewedBy: principal.TenantID + ":" + principal.ObjectID, ReviewedAt: now})
	})
	mux.HandleFunc("DELETE /api/admin/postgres/identities/{objectID}", func(w http.ResponseWriter, r *http.Request) {
		objectID := strings.ToLower(r.PathValue("objectID"))
		if !objectIDPattern.MatchString(objectID) {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_object_id"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		tx, err := db.BeginTx(r.Context(), nil)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM identity_bindings WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), objectID)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM encrypted_secrets WHERE secret_id=?`, postgresSecretID(principal.TenantID, objectID))
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_login_claims WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), objectID)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_profile_tests WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), objectID)
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
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("GET /api/admin/postgres/queries", func(w http.ResponseWriter, _ *http.Request) {
		tools, err := postgres.Catalog(db)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"query_catalog_unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"queries": tools})
	})
	mux.HandleFunc("POST /api/admin/postgres/profiles/preview", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		profile, decodeErr := httpx.DecodeOne[postgres.BusinessProfile](body)
		if err != nil || decodeErr != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_business_profile"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		tool, err := prepareBusinessProfile(ctx, db, encryptionKey, pg, principal, profile)
		if err != nil {
			jsonResponse(w, profilePreparationStatus(err), `{"error":"`+profilePreparationErrorCode(err)+`"}`)
			return
		}
		preview := map[string]any{"version": tool.Version, "sql": tool.SQL, "parameters": tool.Parameters, "outputColumns": tool.OutputColumns, "approvalRecord": tool.ApprovalRecord, "permissionExplanation": "These generated queries run read-only as each mapped user's own PostgreSQL LOGIN. Every user must have SELECT access to mapped columns; organizational row security remains authoritative."}
		var savedProfile postgres.BusinessProfile
		if json.Unmarshal(tool.ProfileConfig, &savedProfile) == nil && savedProfile.Capability == "related_list" {
			parentSQL, compileErr := postgres.CompileRelatedParentLookup(savedProfile)
			if compileErr != nil {
				jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_business_profile"}`)
				return
			}
			preview["parentSQL"] = parentSQL
			preview["parentParameters"] = []postgres.QueryParameter{{Name: "term", Type: "text"}}
		}
		writeJSON(w, http.StatusOK, preview)
	})
	mux.HandleFunc("PUT /api/admin/postgres/profiles", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		profile, decodeErr := httpx.DecodeOne[postgres.BusinessProfile](body)
		if err != nil || decodeErr != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_business_profile"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		tool, err := prepareBusinessProfile(ctx, db, encryptionKey, pg, principal, profile)
		cancel()
		if err != nil {
			jsonResponse(w, profilePreparationStatus(err), `{"error":"`+profilePreparationErrorCode(err)+`"}`)
			return
		}
		parameterJSON, _ := json.Marshal(tool.Parameters)
		outputJSON, _ := json.Marshal(tool.OutputColumns)
		config := tool.ProfileConfig
		tx, err := db.BeginTx(r.Context(), nil)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tool_id) DO UPDATE SET version=excluded.version,description=excluded.description,fixed_sql=excluded.fixed_sql,parameter_schema=excluded.parameter_schema,output_columns=excluded.output_columns,approval_record=excluded.approval_record,profile_config=excluded.profile_config`, tool.ID, tool.Version, tool.Description, tool.SQL, parameterJSON, outputJSON, tool.ApprovalRecord, config)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_profile_tests WHERE tenant_id=? AND tool_id=?`, strings.ToLower(principal.TenantID), tool.ID)
		}
		if err != nil {
			if tx != nil {
				_ = tx.Rollback()
			}
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"query_catalog_unavailable"}`)
			return
		}
		if err := tx.Commit(); err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"query_catalog_unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, tool)
	})
	mux.HandleFunc("PUT /api/admin/postgres/queries", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		tool, decodeErr := httpx.DecodeOne[postgres.QueryTool](body)
		if err != nil || decodeErr != nil || postgres.ValidateQueryTool(tool) != nil {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_approved_query"}`)
			return
		}
		var current int
		err = db.QueryRowContext(r.Context(), `SELECT version FROM query_tools WHERE tool_id=?`, tool.ID).Scan(&current)
		if err != nil && err != sql.ErrNoRows {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"query_catalog_unavailable"}`)
			return
		}
		if err == sql.ErrNoRows && tool.Version != 1 || err == nil && tool.Version != current+1 {
			jsonResponse(w, http.StatusConflict, `{"error":"query_version_conflict"}`)
			return
		}
		parameters, _ := json.Marshal(tool.Parameters)
		outputs, _ := json.Marshal(tool.OutputColumns)
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		approval := strings.TrimSpace(tool.ApprovalRecord) + "; reviewed-by=" + principal.TenantID + ":" + principal.ObjectID
		if len(approval) > 256 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_approved_query"}`)
			return
		}
		_, err = db.ExecContext(r.Context(), `INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config)
VALUES(?,?,?,?,?,?,?,'{}') ON CONFLICT(tool_id) DO UPDATE SET version=excluded.version,description=excluded.description,fixed_sql=excluded.fixed_sql,parameter_schema=excluded.parameter_schema,output_columns=excluded.output_columns,approval_record=excluded.approval_record,profile_config='{}'`, tool.ID, tool.Version, tool.Description, tool.SQL, parameters, outputs, approval)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"query_catalog_unavailable"}`)
			return
		}
		tool.ApprovalRecord = approval
		writeJSON(w, http.StatusOK, tool)
	})
	mux.HandleFunc("DELETE /api/admin/postgres/queries/{toolID}", func(w http.ResponseWriter, r *http.Request) {
		result, err := db.ExecContext(r.Context(), `DELETE FROM query_tools WHERE tool_id=?`, r.PathValue("toolID"))
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"query_catalog_unavailable"}`)
			return
		}
		deleted, err := result.RowsAffected()
		if err != nil || deleted == 0 {
			jsonResponse(w, http.StatusNotFound, `{"error":"query_not_found"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	return mux
}

func postgresCredentialHandler(db *sql.DB, encryptionKey []byte, pg *postgres.Connector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/postgres/credentials", func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		if pg.SharedCredentialsConfigured() {
			adapter, err := loadPostgresAdapter(db)
			if err != nil {
				jsonResponse(w, 503, `{"error":"adapter_unavailable"}`)
				return
			}
			state := "adapter_required"
			mapped := false
			var resolved postgres.ResolvedIdentity
			if adapter != nil {
				state = "email_required"
				if principal.VerifiedEmail != "" {
					state = "user_not_authorized"
					scoped, login, password, accessErr := postgresAccess(r.Context(), db, encryptionKey, pg, principal)
					if accessErr == nil {
						resolved, accessErr = scoped.ResolveIdentity(r.Context(), login, password)
					}
					mapped = accessErr == nil
					if mapped {
						state = "connected"
					}
				}
			}
			writeJSON(w, 200, map[string]any{"available": true, "mapped": mapped, "configured": mapped, "verifiedEmail": principal.VerifiedEmail, "emailStatus": principal.DirectoryEmailStatus, "mode": "shared-adapter", "status": state, "userId": resolved.UserID, "databaseRole": resolved.Role})
			return
		}
		mapped := false
		if principal.VerifiedEmail != "" {
			_, mappingErr := mappedDatabaseIdentity(r.Context(), db, principal)
			mapped = mappingErr == nil
		}
		_, err := loadPostgresPassword(db, encryptionKey, principal.TenantID, principal.ObjectID)
		writeJSON(w, http.StatusOK, map[string]any{"available": pg != nil, "mapped": mapped, "configured": err == nil, "verifiedEmail": principal.VerifiedEmail})
	})
	mux.HandleFunc("PUT /api/postgres/credentials", func(w http.ResponseWriter, r *http.Request) {
		if pg == nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"postgres_not_configured"}`)
			return
		}
		if pg.SharedCredentialsConfigured() {
			jsonResponse(w, 409, `{"error":"shared_adapter_does_not_use_user_passwords"}`)
			return
		}
		body, err := ioReadRequest(r)
		input, decodeErr := httpx.DecodeOne[postgresCredentialInput](body)
		if err != nil || decodeErr != nil || len(input.Password) == 0 || len(input.Password) > 4096 || strings.ContainsRune(input.Password, 0) {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_database_credential"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		databaseIdentity, err := mappedDatabaseIdentity(r.Context(), db, principal)
		if err != nil {
			jsonResponse(w, http.StatusConflict, `{"error":"reviewed_identity_binding_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := pg.CheckIdentity(ctx, databaseIdentity, input.Password); err != nil {
			jsonResponse(w, http.StatusFailedDependency, `{"error":"database_identity_check_failed"}`)
			return
		}
		if err := storePostgresCredential(r.Context(), db, encryptionKey, principal, databaseIdentity, input.Password); err != nil {
			if errors.Is(err, errIdentityBindingChanged) {
				jsonResponse(w, http.StatusConflict, `{"error":"identity_mapping_changed"}`)
				return
			}
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
	})
	mux.HandleFunc("DELETE /api/postgres/credentials", func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		tx, err := db.BeginTx(r.Context(), nil)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM encrypted_secrets WHERE secret_id=?`, postgresSecretID(principal.TenantID, principal.ObjectID))
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_profile_tests WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), strings.ToLower(principal.ObjectID))
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

func postgresProfilesHandler(db *sql.DB, encryptionKey []byte, pg *postgres.Connector) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		tools, err := approvedPostgresToolsForUser(r.Context(), db, encryptionKey, pg, principal)
		if err != nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"profile_catalog_unavailable"}`)
			return
		}
		profiles := make([]map[string]any, 0)
		for _, tool := range tools {
			if len(tool.ProfileConfig) == 0 || string(tool.ProfileConfig) == "{}" {
				continue
			}
			var p postgres.BusinessProfile
			if json.Unmarshal(tool.ProfileConfig, &p) == nil {
				profiles = append(profiles, map[string]any{"id": p.ID, "version": p.Version, "label": p.Label, "capability": p.Capability})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
	})
}

const maxPostgresToolsForUserSelector = 32

// approvedPostgresToolsForUser only returns metadata that the user's own login can
// execute against its current schema. This keeps the model's catalog tenant-safe.
func approvedPostgresToolsForUser(ctx context.Context, db *sql.DB, encryptionKey []byte, pg *postgres.Connector, principal identity.Principal) ([]postgres.QueryTool, error) {
	tools, err := postgres.Catalog(db)
	if err != nil {
		return nil, err
	}
	if len(tools) > maxPostgresToolsForUserSelector {
		return nil, errors.New("PostgreSQL tool catalog exceeds the per-user selector limit")
	}
	if pg == nil {
		return nil, errors.New("PostgreSQL is unavailable")
	}
	checkAllCtx, cancelAll := context.WithTimeout(ctx, 20*time.Second)
	defer cancelAll()
	pg, login, password, err := postgresAccess(ctx, db, encryptionKey, pg, principal)
	if err != nil {
		return nil, err
	}
	approved := make([]postgres.QueryTool, 0, len(tools))
	for _, tool := range tools {
		if checkAllCtx.Err() != nil {
			return nil, errors.New("PostgreSQL profile access checks exceeded their time budget")
		}
		checkCtx, cancel := context.WithTimeout(checkAllCtx, 4*time.Second)
		var checkErr error
		if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" {
			var profile postgres.BusinessProfile
			if json.Unmarshal(tool.ProfileConfig, &profile) == nil {
				var fingerprint string
				fingerprint, checkErr = pg.ProfileSchemaFingerprint(checkCtx, login, password, profile)
				if checkErr == nil && fingerprint != profile.SchemaFingerprint {
					checkErr = errors.New("profile schema fingerprint mismatch")
				}
			} else {
				checkErr = errors.New("invalid profile")
			}
		} else {
			checkErr = checkPostgresTool(checkCtx, pg, login, password, tool)
		}
		cancel()
		if checkErr == nil {
			approved = append(approved, tool)
		}
	}
	return postgres.FilterProfileReferences(approved), nil
}

func postgresProfileTestHandler(db *sql.DB, encryptionKey []byte, pg *postgres.Connector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/postgres/profiles/{toolID}/test", func(w http.ResponseWriter, r *http.Request) {
		body, bodyErr := ioReadRequest(r)
		if bodyErr != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		if pg == nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"postgres_not_configured"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		if pg.SharedCredentialsConfigured() {
			testAdapterProfile(w, r, db, encryptionKey, pg, principal)
			return
		}
		snapshot, password, err := loadProfileTestSnapshot(r.Context(), db, encryptionKey, principal, r.PathValue("toolID"))
		if err != nil {
			jsonResponse(w, http.StatusConflict, `{"error":"reviewed_identity_and_own_credentials_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		testErr := testBusinessProfile(ctx, pg, snapshot.login, password, snapshot.profile)
		outcome, category := "passed", ""
		if testErr != nil {
			outcome, category = "failed", "permission_or_schema_check_failed"
		}
		if err := saveProfileTestEvidence(r.Context(), db, snapshot, outcome, category); err != nil {
			if errors.Is(err, errProfileTestStale) {
				jsonResponse(w, http.StatusConflict, `{"error":"profile_test_stale"}`)
				return
			}
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"profile_test_not_saved"}`)
			return
		}
		status := http.StatusOK
		if outcome != "passed" {
			status = http.StatusFailedDependency
		}
		writeJSON(w, status, map[string]string{"profileId": snapshot.profile.ID, "status": outcome, "category": category})
	})
	return mux
}

type profileTestSnapshot struct {
	tenantID, objectID, login, email, reviewedAt, credentialGeneration, profileGeneration string
	profile                                                                               postgres.BusinessProfile
}

var errProfileTestStale = errors.New("profile test inputs changed while the test was running")

func loadProfileTestSnapshot(ctx context.Context, db *sql.DB, encryptionKey []byte, principal identity.Principal, toolID string) (profileTestSnapshot, string, error) {
	snapshot := profileTestSnapshot{tenantID: strings.ToLower(principal.TenantID), objectID: strings.ToLower(principal.ObjectID)}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snapshot, "", err
	}
	defer tx.Rollback()
	var profileJSON []byte
	var login, email, reviewedAt string
	var ciphertext, nonce []byte
	if err := tx.QueryRowContext(ctx, `SELECT q.profile_config,b.database_identity,b.verified_email,b.reviewed_at,s.ciphertext,s.nonce,s.updated_at FROM query_tools q JOIN identity_bindings b ON b.tenant_id=? AND b.object_id=? AND b.verified_email=? JOIN encrypted_secrets s ON s.secret_id=? WHERE q.tool_id=? AND q.profile_config<>'{}' AND (SELECT COUNT(*) FROM identity_bindings b2 WHERE b2.tenant_id=b.tenant_id AND b2.database_identity=b.database_identity)=1`, snapshot.tenantID, snapshot.objectID, principal.VerifiedEmail, postgresSecretID(snapshot.tenantID, snapshot.objectID), toolID).Scan(&profileJSON, &login, &email, &reviewedAt, &ciphertext, &nonce, &snapshot.credentialGeneration); err != nil {
		return snapshot, "", err
	}
	if !postgres.ValidDatabaseIdentity(login) {
		return snapshot, "", errors.New("invalid mapped identity")
	}
	if err := json.Unmarshal(profileJSON, &snapshot.profile); err != nil {
		return snapshot, "", err
	}
	fingerprint, err := postgres.ProfileFingerprint(snapshot.profile)
	if err != nil {
		return snapshot, "", err
	}
	snapshot.profileGeneration, snapshot.login, snapshot.email, snapshot.reviewedAt = fingerprint, login, email, reviewedAt
	password, err := decrypt(encryptionKey, nonce, ciphertext)
	if err != nil || len(password) == 0 || strings.ContainsRune(string(password), 0) {
		return snapshot, "", errors.New("stored PostgreSQL credentials are invalid")
	}
	if err := tx.Commit(); err != nil {
		return snapshot, "", err
	}
	return snapshot, string(password), nil
}

func saveProfileTestEvidence(ctx context.Context, db *sql.DB, snapshot profileTestSnapshot, outcome, category string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var login, email, reviewedAt, credentialGeneration string
	var profileJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT b.database_identity,b.verified_email,b.reviewed_at,s.updated_at,q.profile_config FROM identity_bindings b JOIN encrypted_secrets s ON s.secret_id=? JOIN query_tools q ON q.tool_id=? WHERE b.tenant_id=? AND b.object_id=?`, postgresSecretID(snapshot.tenantID, snapshot.objectID), snapshot.profile.ID, snapshot.tenantID, snapshot.objectID).Scan(&login, &email, &reviewedAt, &credentialGeneration, &profileJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return errProfileTestStale
	}
	if err != nil {
		return err
	}
	var profile postgres.BusinessProfile
	if err := json.Unmarshal(profileJSON, &profile); err != nil {
		return err
	}
	fingerprint, err := postgres.ProfileFingerprint(profile)
	if err != nil {
		return err
	}
	if login != snapshot.login || email != snapshot.email || reviewedAt != snapshot.reviewedAt || credentialGeneration != snapshot.credentialGeneration || fingerprint != snapshot.profileGeneration {
		return errProfileTestStale
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO postgres_profile_tests(tenant_id,tool_id,profile_version,object_id,database_identity,schema_fingerprint,tested_at,outcome,error_category,binding_email,binding_reviewed_at,credential_generation,profile_generation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,tool_id,profile_version,object_id) DO UPDATE SET database_identity=excluded.database_identity,schema_fingerprint=excluded.schema_fingerprint,tested_at=excluded.tested_at,outcome=excluded.outcome,error_category=excluded.error_category,binding_email=excluded.binding_email,binding_reviewed_at=excluded.binding_reviewed_at,credential_generation=excluded.credential_generation,profile_generation=excluded.profile_generation`, snapshot.tenantID, snapshot.profile.ID, snapshot.profile.Version, snapshot.objectID, snapshot.login, snapshot.profileGeneration, time.Now().UTC().Format(time.RFC3339Nano), outcome, category, snapshot.email, snapshot.reviewedAt, snapshot.credentialGeneration, snapshot.profileGeneration)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func checkPostgresTool(ctx context.Context, pg *postgres.Connector, login, password string, tool postgres.QueryTool) error {
	if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" {
		var profile postgres.BusinessProfile
		if err := json.Unmarshal(tool.ProfileConfig, &profile); err != nil {
			return err
		}
		err := testBusinessProfile(ctx, pg, login, password, profile)
		return err
	}
	_, err := pg.Search(ctx, login, password, "IQKB setup check no-match", 1, tool)
	return err
}

func testBusinessProfile(ctx context.Context, pg *postgres.Connector, login, password string, profile postgres.BusinessProfile) error {
	if profile.Capability != "related_list" {
		_, err := pg.SearchProfile(ctx, login, password, profile.Label, 1, profile)
		return err
	}
	if err := pg.ValidateRelatedProfile(ctx, login, password, profile); err != nil {
		return err
	}
	filters := make(map[string]string, len(profile.Relationship.Filters))
	for _, filter := range profile.Relationship.Filters {
		if len(filter.Values) == 0 {
			return errInvalidBusinessProfile
		}
		filters[filter.Name] = filter.Values[0].Value
	}
	_, _, err := pg.SearchRelatedProfile(ctx, login, password, profile.Label, 1, filters, profile)
	return err
}

var errIdentityBindingChanged = errors.New("identity binding changed")

func storePostgresCredential(ctx context.Context, db *sql.DB, encryptionKey []byte, principal identity.Principal, databaseIdentity, password string) error {
	nonce, ciphertext, err := encrypt(encryptionKey, []byte(password))
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentIdentity string
	err = tx.QueryRowContext(ctx, `SELECT database_identity FROM identity_bindings WHERE tenant_id=? AND object_id=? AND verified_email=?`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail).Scan(&currentIdentity)
	if errors.Is(err, sql.ErrNoRows) || err == nil && currentIdentity != databaseIdentity {
		return errIdentityBindingChanged
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO encrypted_secrets(secret_id,ciphertext,nonce,updated_at) VALUES(?,?,?,?) ON CONFLICT(secret_id) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,updated_at=excluded.updated_at`, postgresSecretID(principal.TenantID, principal.ObjectID), ciphertext, nonce, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM postgres_profile_tests WHERE tenant_id=? AND object_id=?`, strings.ToLower(principal.TenantID), strings.ToLower(principal.ObjectID)); err != nil {
		return err
	}
	return tx.Commit()
}

func postgresCheckHandler(db *sql.DB, encryptionKey []byte, pg *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		if pg == nil {
			jsonResponse(w, http.StatusServiceUnavailable, `{"error":"postgres_not_configured"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		pg, databaseIdentity, password, err := postgresAccess(r.Context(), db, encryptionKey, pg, principal)
		if err != nil {
			jsonResponse(w, http.StatusConflict, `{"error":"database_credentials_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := pg.CheckIdentity(ctx, databaseIdentity, password); err != nil {
			jsonResponse(w, http.StatusFailedDependency, `{"error":"database_identity_check_failed"}`)
			return
		}
		tools, err := postgres.Catalog(db)
		if err != nil || len(tools) == 0 {
			jsonResponse(w, http.StatusFailedDependency, `{"error":"approved_query_required"}`)
			return
		}
		for _, tool := range tools {
			if err := checkPostgresTool(ctx, pg, databaseIdentity, password, tool); err != nil {
				jsonResponse(w, http.StatusFailedDependency, `{"error":"approved_query_check_failed"}`)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "connected"})
	}
}

func validVerifiedEmail(email string) bool {
	return len(email) <= 254 && email == strings.ToLower(strings.TrimSpace(email)) && emailPattern.MatchString(email)
}

func mappedDatabaseIdentity(ctx context.Context, db *sql.DB, principal identity.Principal) (string, error) {
	if principal.VerifiedEmail == "" {
		return "", errors.New("verified organizational email is required")
	}
	var databaseIdentity string
	err := db.QueryRowContext(ctx, `SELECT database_identity FROM identity_bindings WHERE tenant_id=? AND object_id=? AND verified_email=?`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail).Scan(&databaseIdentity)
	if err != nil || !postgres.ValidDatabaseIdentity(databaseIdentity) {
		return "", errors.New("reviewed database identity is missing")
	}
	var duplicates int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_bindings WHERE tenant_id=? AND database_identity=?`, principal.TenantID, databaseIdentity).Scan(&duplicates); err != nil || duplicates != 1 {
		return "", errors.New("database login mapping is ambiguous")
	}
	return databaseIdentity, nil
}

func postgresSecretID(tenantID, objectID string) string {
	return "postgres_password:" + strings.ToLower(tenantID) + ":" + strings.ToLower(objectID)
}

func loadPostgresPassword(db *sql.DB, encryptionKey []byte, tenantID, objectID string) (string, error) {
	var ciphertext, nonce []byte
	if err := db.QueryRow(`SELECT ciphertext,nonce FROM encrypted_secrets WHERE secret_id=?`, postgresSecretID(tenantID, objectID)).Scan(&ciphertext, &nonce); err != nil {
		return "", err
	}
	password, err := decrypt(encryptionKey, nonce, ciphertext)
	if err != nil || len(password) == 0 || strings.ContainsRune(string(password), 0) {
		return "", errors.New("stored PostgreSQL credentials are invalid")
	}
	return string(password), nil
}

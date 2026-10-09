package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

type postgresReadiness struct {
	Enabled bool   `json:"enabled"`
	Ready   bool   `json:"ready"`
	State   string `json:"state"`
	Message string `json:"message"`
	Next    string `json:"next,omitempty"`
	Queries int    `json:"queries"`
}

func postgresReadinessHandler(db *sql.DB, key []byte, connector *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		result := postgresReadiness{State: "not_selected", Message: "PostgreSQL search is not selected."}
		var err error
		result.Enabled, err = postgresEnabled(db)
		if err != nil {
			jsonResponse(w, 503, `{"error":"source_setting_unavailable"}`)
			return
		}
		if !result.Enabled {
			writeJSON(w, 200, result)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		fail := func(state, message, next string) {
			result.State = state
			result.Message = message
			result.Next = next
			writeJSON(w, 200, result)
		}
		if connector == nil {
			fail("postgres_not_configured", "PostgreSQL is selected, but the shared database connection is not configured.", "postgres-authorization")
			return
		}
		scoped, login, password, err := postgresAccess(ctx, db, key, connector, principal)
		if err != nil {
			state := postgresAccessFailureCode(err, "database_credentials_required")
			switch state {
			case "database_permission_mapping_required":
				adapter, adapterErr := loadPostgresAdapter(db)
				if adapterErr == nil && adapter != nil && adapter.Mode == "application_rules" {
					mapped, _, _, mappingErr := postgresMappedAccess(ctx, db, key, connector, principal)
					if mappingErr == nil {
						if mapped.PermissionSourceConfigured() {
							preview, previewErr := mapped.PreviewAutomaticPermissions(ctx)
							if previewErr != nil {
								fail(postgres.AuthorizationFailureCode(previewErr), "The native permission source could not authorize this account. Refresh my permissions to check the existing application's decision; manual selections cannot override it.", "application-permissions")
							} else {
								fail("native_permissions_ready", fmt.Sprintf("Native permitted fields and row access are selected for database user %s. Save permissions and continue to recheck your matched email and create a search profile.", preview.UserID), "application-permissions")
							}
							return
						}
						user, lookupErr := mapped.RecognizeUser(ctx)
						if lookupErr == nil {
							drafts := 0
							for _, rule := range adapter.Rules {
								if rule.Label == user.ApplicationRole {
									drafts++
								}
							}
							if drafts == 0 {
								fail("application_resource_required", fmt.Sprintf("Your email matches database user %s, label %q. No readable resource is configured for this label. Choose your first table under this label, select its permitted fields and row access, then save permissions and continue.", user.UserID, user.ApplicationRole), "application-permissions")
							} else {
								fail("application_rule_review_required", fmt.Sprintf("Your email matches label %q. Complete the fields and row access in its resource rule, mark the rule reviewed, then save permissions and continue.", user.ApplicationRole), "application-permissions")
							}
							return
						}
					}
				}
				fail(state, "Your email is matched. Configure an existing database-role mapping, or select Application permissions and review resource, field and row rules matching the native application. Unresolved labels remain denied. PostgreSQL is read-only.", "postgres-authorization")
			case "database_email_confirmation_required":
				fail(state, "PostgreSQL is selected. Verify your database email before enabling queries for your account.", "database-access")
			case "postgres_verified_email_required":
				fail(state, "PostgreSQL is selected, but your Microsoft account has no verified organizational email.", "database-access")
			default:
				fail(state, "PostgreSQL is selected, but the authorization mapping or your database credentials are incomplete.", "postgres-authorization")
			}
			return
		}
		if _, err = scoped.ResolveIdentity(ctx, login, password); err != nil {
			if scoped.PermissionSourceConfigured() {
				fail(postgres.AuthorizationFailureCode(err), "The native permission source or its mapped resources could not pass the current user's access check. Refresh my permissions and check the native application's decision.", "application-permissions")
				return
			}
			fail(postgres.AuthorizationFailureCode(err), "The database identity or execution role check failed. Review the mapping and recheck your access.", "postgres-authorization")
			return
		}
		tools, err := postgres.Catalog(db)
		if err != nil {
			fail("query_catalog_unavailable", "The approved query catalog could not be loaded.", "postgres-query-catalog")
			return
		}
		result.Queries = len(tools)
		if len(tools) == 0 {
			next := "postgres-query-catalog"
			adapter, _ := loadPostgresAdapter(db)
			if adapter != nil && adapter.Mode == "application_rules" {
				next = "business-search-profile"
			}
			fail("approved_query_required", "Your database identity is verified. Create and save a business search profile from your permitted resources to make them searchable.", next)
			return
		}
		if !postgresProfilesReady(ctx, db, connector, principal.TenantID, tools) {
			fail("second_user_test_required", "Business profiles require passing tests from two distinct mapped database users.", "database-access")
			return
		}
		for _, tool := range tools {
			if err = checkPostgresTool(ctx, scoped, login, password, tool); err != nil {
				fail("approved_query_check_failed", "A saved query could not pass its schema and permission checks for your account.", "postgres-query-catalog")
				return
			}
		}
		result.Ready = true
		result.State = "ready"
		result.Message = "PostgreSQL is ready for workspace activation. Your identity, approved queries, and permission checks passed."
		writeJSON(w, 200, result)
	}
}

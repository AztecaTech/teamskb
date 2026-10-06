package postgres

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func FuzzBusinessProfileIdentifierQuoting(f *testing.F) {
	for _, identifier := range []string{"assets", `asset"; DROP TABLE users;--`, "schema.with.dot", "quoted name", strings.Repeat("x", 63), strings.Repeat("x", 64)} {
		f.Add(identifier)
	}
	f.Fuzz(func(t *testing.T, identifier string) {
		p := BusinessProfile{
			ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup",
			Schema: identifier, Relation: identifier, KeyColumn: identifier, LabelColumn: identifier,
			SearchColumns: []string{identifier}, ReturnColumns: []ProfileColumn{{Name: identifier, Type: "text"}}, Approval: "fuzz-test",
		}
		if err := ValidateBusinessProfile(p); err != nil {
			return
		}
		query, err := CompileBusinessProfile(p)
		if err != nil {
			t.Fatalf("validated profile failed compilation: %v", err)
		}
		quotedRelation := (pgx.Identifier{identifier, identifier}).Sanitize()
		quotedIdentifier := (pgx.Identifier{identifier}).Sanitize()
		if !strings.Contains(query, quotedRelation) || strings.Count(query, quotedIdentifier) < 4 ||
			!strings.HasPrefix(query, "SELECT ") || !strings.Contains(query, " LIMIT $2") {
			t.Fatalf("compiler did not preserve quoted identifiers and one bounded SELECT: %q", query)
		}
	})
}

func TestCompileBusinessProfileQuotesIdentifiersAndKeepsValuesBound(t *testing.T) {
	p := BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: `org"x`, Relation: "asset list", KeyColumn: "asset_id", LabelColumn: "display name", SearchColumns: []string{"display name"}, ReturnColumns: []ProfileColumn{{Name: "status", Type: "text"}}, Approval: "ticket-42"}
	sql, err := CompileBusinessProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"org""x"."asset list"`, `COALESCE("display name"::text,'') ILIKE '%' || $1 || '%'`, `lower(("asset_id")::text)=lower($1)`, `lower(("display name")::text)=lower($1)`, `CASE WHEN lower(("asset_id")::text)=lower($1) THEN 1.0`, `AS relevance`, `ORDER BY (CASE WHEN lower(("asset_id")::text)=lower($1) THEN 1.0`, `LIMIT $2`} {
		if !strings.Contains(sql, want) {
			t.Fatalf("compiled SQL missing %q: %s", want, sql)
		}
	}
	if strings.Contains(sql, "ticket-42") || strings.Contains(sql, "Acme") {
		t.Fatalf("profile values leaked into SQL: %s", sql)
	}
}

func TestBusinessProfileSourceURLMustBeSelectedTextOutput(t *testing.T) {
	p := BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: "ops", Relation: "assets", KeyColumn: "id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []ProfileColumn{{Name: "source_url", Type: "text"}}, SourceURLColumn: "source_url", Approval: "ticket"}
	if err := ValidateBusinessProfile(p); err != nil {
		t.Fatalf("selected text source URL was rejected: %v", err)
	}
	p.SourceURLColumn = "hidden_url"
	if ValidateBusinessProfile(p) == nil {
		t.Fatal("source URL column not selected for output was accepted")
	}
	p.SourceURLColumn = "source_url"
	p.ReturnColumns[0].Type = "timestamp"
	if ValidateBusinessProfile(p) == nil {
		t.Fatal("non-text source URL output was accepted")
	}
}

func TestRelatedProfileCompilesOneReviewedJoinAndBindsTypedFilters(t *testing.T) {
	p := BusinessProfile{ID: "invoice_list", Version: 1, Label: "Invoice", Capability: "related_list", Schema: "billing", Relation: "invoices", KeyColumn: "invoice_id", LabelColumn: "invoice_number", ReturnColumns: []ProfileColumn{{Name: "amount", Type: "number"}}, Approval: "ticket-42", Relationship: &RelatedRelationship{ParentProfileID: "customer_lookup", ParentSchema: "crm", ParentRelation: "customers", ParentKeyColumn: "customer_id", ParentLabelColumn: "name", ParentSearchColumns: []string{"name", "email"}, ChildForeignKey: "customer_id", Filters: []ProfileFilter{{Name: "payment", Column: "status", Type: "text", Required: true, Values: []ProfileFilterValue{{Label: "Unpaid", Value: "open"}, {Label: "Paid", Value: "closed"}}}}}}
	query, err := CompileBusinessProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"billing"."invoices"`, `"customer_id"=$1::text`, `"status"=$2`, `LIMIT $3`} {
		if !strings.Contains(query, want) {
			t.Fatalf("related-list SQL missing %q: %s", want, query)
		}
	}
	if strings.Contains(query, "open") || strings.Contains(query, "ticket-42") {
		t.Fatalf("business value leaked into SQL: %s", query)
	}
	params := ProfileParameters(p)
	if len(params) != 3 || params[0].Name != "parent_key" || params[1].Name != "filter_payment" || params[1].Type != "text" || params[2].Name != "limit" {
		t.Fatalf("unexpected related query parameters: %#v", params)
	}
	lookup, err := CompileRelatedParentLookup(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`FROM "crm"."customers" WHERE lower(("customer_id")::text)=lower($1)`, `WHERE lower(("name")::text)=lower($1)`, `WHERE NOT EXISTS(SELECT 1 FROM exact_key)`, `ORDER BY rank,id LIMIT 2`} {
		if !strings.Contains(lookup, want) {
			t.Fatalf("parent lookup SQL missing %q: %s", want, lookup)
		}
	}
	p.Relationship.Filters[0].Values[0].Value = "not-a-date"
	p.Relationship.Filters[0].Type = "date"
	if ValidateBusinessProfile(p) == nil {
		t.Fatal("filter value with wrong type accepted")
	}
}

func TestRelatedProfileCastsBoundKeyToDiscoveredDatabaseType(t *testing.T) {
	p := BusinessProfile{ID: "event_list", Version: 1, Label: "Event", Capability: "related_list", Schema: "ops", Relation: "events", KeyColumn: "id", LabelColumn: "name", ReturnColumns: []ProfileColumn{{Name: "name", Type: "text"}}, Approval: "ticket", Relationship: &RelatedRelationship{ParentProfileID: "asset_lookup", ParentSchema: "ops", ParentRelation: "assets", ParentKeyColumn: "id", ParentLabelColumn: "name", ParentSearchColumns: []string{"name"}, ChildForeignKey: "asset_id", ChildForeignKeyType: "integer", Filters: []ProfileFilter{{Name: "kind", Column: "kind", Type: "text", Required: true, Values: []ProfileFilterValue{{Label: "repair", Value: "repair"}}}}}}
	p.Relationship.ParentKeyType = "bigint"
	query, err := CompileBusinessProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, `"asset_id"=$1::bigint`) {
		t.Fatalf("related query does not preserve the typed FK index predicate: %s", query)
	}
	p.Relationship.ChildForeignKeyType = "integer); DROP TABLE events;--"
	if _, err := CompileBusinessProfile(p); err == nil {
		t.Fatal("accepted an untrusted SQL type")
	}
}

func TestCompileBusinessProfileSupportsExplicitFullTextStrategy(t *testing.T) {
	p := BusinessProfile{ID: "policy_search", Version: 1, Label: "Policy", Capability: "text_search", SearchStrategy: "full_text", Language: "english", Schema: "public", Relation: "policies", KeyColumn: "policy_id", LabelColumn: "title", SearchColumns: []string{"title", "body"}, ReturnColumns: []ProfileColumn{{Name: "state", Type: "text"}}, Approval: "ticket"}
	query, err := CompileBusinessProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"to_tsvector('pg_catalog.english'::regconfig,COALESCE(\"title\"::text,''))", "websearch_to_tsquery('pg_catalog.english'::regconfig,$1)", "ts_rank_cd(to_tsvector('pg_catalog.english'::regconfig,COALESCE(\"title\"::text,'')),websearch_to_tsquery('pg_catalog.english'::regconfig,$1))", "AS relevance", `ORDER BY (LEAST(1.0,GREATEST(`, `DESC, "policy_id" LIMIT $2`} {
		if !strings.Contains(query, want) {
			t.Fatalf("full-text SQL missing %q: %s", want, query)
		}
	}
	p.Language = "english'); DROP TABLE policies; --"
	if _, err := CompileBusinessProfile(p); err == nil {
		t.Fatal("unapproved text-search language accepted")
	}
	p.Language, p.SearchStrategy = "", "keyword"
	query, err = CompileBusinessProfile(p)
	if err != nil || !strings.Contains(query, `COALESCE("title"::text,'') ILIKE '%' || $1 || '%'`) {
		t.Fatalf("keyword strategy SQL=%s err=%v", query, err)
	}
}

func TestCompileBusinessProfileRejectsUnknownTypesAndIdentifiers(t *testing.T) {
	p := BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: "public", Relation: "assets", KeyColumn: "id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []ProfileColumn{{Name: "status", Type: "text"}}, Approval: "ticket"}
	if _, err := CompileBusinessProfile(p); err != nil {
		t.Fatal(err)
	}
	p.ReturnColumns[0].Type = "text); DROP TABLE assets;--"
	if _, err := CompileBusinessProfile(p); err == nil {
		t.Fatal("unknown output type accepted")
	}
	p.ReturnColumns[0].Type = "text"
	p.Relation = `assets"; DROP TABLE users;--`
	if _, err := CompileBusinessProfile(p); err != nil {
		t.Fatalf("quoted identifier should be safe: %v", err)
	}
	query, err := CompileBusinessProfile(p)
	if err != nil || !strings.Contains(query, `"assets""; DROP TABLE users;--"`) {
		t.Fatalf("identifier not quoted: %s err=%v", query, err)
	}
}

func TestTypedProfileAttributesParseToNativeValues(t *testing.T) {
	for _, tc := range []struct {
		raw, kind string
		want      any
	}{{"42", "integer", int64(42)}, {"3.5", "number", float64(3.5)}, {"true", "boolean", true}, {"active", "text", "active"}} {
		got, err := parseProfileAttribute(tc.raw, tc.kind)
		if err != nil || got != tc.want {
			t.Errorf("parse %s %s = %#v, %v", tc.raw, tc.kind, got, err)
		}
	}
	if _, err := parseProfileAttribute("not-an-int", "integer"); err == nil {
		t.Fatal("invalid typed value accepted")
	}
}

func TestProfileSchemaSupportsCommonStableKeyTypes(t *testing.T) {
	for _, actual := range []string{"text", "character varying", "uuid", "integer", "bigint"} {
		if !profileTypeMatches("key", actual) {
			t.Errorf("stable key type %q rejected", actual)
		}
	}
	for _, actual := range []string{"jsonb", "bytea", "numeric[]"} {
		if profileTypeMatches("key", actual) {
			t.Errorf("unsupported key type %q accepted", actual)
		}
	}
}

func TestEntityLookupAlwaysFetchesEnoughCandidatesToDetectAmbiguity(t *testing.T) {
	if got := profileCandidateLimit("entity_lookup", 1); got != 2 {
		t.Fatalf("limit-one entity lookup fetched %d candidate(s)", got)
	}
	if got := profileCandidateLimit("entity_lookup", 4); got != 4 {
		t.Fatalf("entity lookup limit changed to %d", got)
	}
	if got := profileCandidateLimit("text_search", 1); got != 1 {
		t.Fatalf("text-search budget unexpectedly changed to %d", got)
	}
}

func TestSchemaMetadataFingerprintIgnoresCatalogRowOrder(t *testing.T) {
	first := []string{"relation=42", "column=id|uuid|1|true", "column=name|text|2|false"}
	second := []string{"column=name|text|2|false", "relation=42", "column=id|uuid|1|true"}
	if schemaMetadataFingerprint(first) != schemaMetadataFingerprint(second) {
		t.Fatal("schema fingerprint changed with catalog row order")
	}
}

func TestTimestampParserAcceptsHourOnlyPostgresOffsets(t *testing.T) {
	for _, raw := range []string{"2026-10-05 12:30:00-07", "2026-10-05 12:30:00.123456-07", "2026-10-05 19:30:00+00"} {
		if _, err := parseProfileAttribute(raw, "timestamp"); err != nil {
			t.Errorf("timestamp %q rejected: %v", raw, err)
		}
	}
}

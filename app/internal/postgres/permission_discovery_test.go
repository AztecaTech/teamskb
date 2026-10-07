package postgres

import "testing"

func TestAuditRelationshipsAreNotPermissionEvidence(t *testing.T) {
	result := PermissionDiscovery{Relations: []PermissionRelation{{Schema: "public", Relation: "notes", Columns: []string{"id", "created_by"}}, {Schema: "public", Relation: "rules", Columns: []string{"role_id", "permission"}}}, Relationships: []DiscoveredRelationship{{SourceSchema: "public", SourceRelation: "notes", SourceColumns: []string{"created_by"}, TargetSchema: "public", TargetRelation: "people"}}}
	classifyPermissionEvidence(&result, "public", "people")
	if result.Relations[0].Evidence != "audit references only; no access rule demonstrated" {
		t.Fatal("creator relationship was presented as access control")
	}
	if result.Relations[1].Evidence != "permission-related fields; authorization meaning requires review" {
		t.Fatal("permission structure was not distinguished from auditing")
	}
}

package postgres

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelatedListSelectionMapsReviewedFilterLabels(t *testing.T) {
	p := BusinessProfile{ID: "invoice_list", Version: 1, Label: "Invoice", Capability: "related_list", Schema: "billing", Relation: "invoices", KeyColumn: "invoice_id", LabelColumn: "invoice_number", ReturnColumns: []ProfileColumn{{Name: "amount", Type: "number"}}, Approval: "ticket-42", SchemaFingerprint: strings.Repeat("a", 64), Relationship: &RelatedRelationship{ParentProfileID: "customer_lookup", ParentSchema: "crm", ParentRelation: "customers", ParentKeyColumn: "customer_id", ParentLabelColumn: "name", ParentSearchColumns: []string{"name"}, ChildForeignKey: "customer_id", Filters: []ProfileFilter{{Name: "payment", Column: "status", Type: "text", Required: true, Values: []ProfileFilterValue{{Label: "Unpaid", Value: "open"}, {Label: "Paid", Value: "closed"}}}}}}
	p.Relationship.Filters = append(p.Relationship.Filters, ProfileFilter{Name: "region", Column: "region_code", Type: "text", Values: []ProfileFilterValue{{Label: "West", Value: "W"}, {Label: "East", Value: "E"}}})
	config, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	query, err := CompileBusinessProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	tool := QueryTool{ID: p.ID, Version: p.Version, Description: p.Label, SQL: query, Parameters: ProfileParameters(p), OutputColumns: ProfileOutputColumns(p), ApprovalRecord: "reviewed", ProfileConfig: config}
	if err := ValidateQueryTool(tool); err != nil {
		t.Fatal(err)
	}
	parent := BusinessProfile{ID: "customer_lookup", Version: 1, Label: "Customer", Capability: "entity_lookup", Schema: "crm", Relation: "customers", KeyColumn: "customer_id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []ProfileColumn{{Name: "email", Type: "text"}}, Approval: "reviewed", SchemaFingerprint: strings.Repeat("a", 64)}
	parentConfig, _ := json.Marshal(parent)
	parentSQL, _ := CompileBusinessProfile(parent)
	parentTool := QueryTool{ID: parent.ID, Version: parent.Version, Description: parent.Label, SQL: parentSQL, Parameters: ProfileParameters(parent), OutputColumns: ProfileOutputColumns(parent), ApprovalRecord: "reviewed", ProfileConfig: parentConfig}
	tools := []QueryTool{parentTool, tool}
	if err := ValidateProfileReferences(tools); err != nil {
		t.Fatal(err)
	}
	prompt, err := SelectionPrompt("show unpaid invoices for Acme", tools)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "Unpaid") || !strings.Contains(prompt, "filters.payment") || !strings.Contains(prompt, "parentEntityLabel") || !strings.Contains(prompt, "Customer") {
		t.Fatalf("selector prompt omitted reviewed filter values: %s", prompt)
	}
	if got := FilterProfileReferences([]QueryTool{tool}); len(got) != 0 {
		t.Fatalf("related profile without its approved parent remained selectable: %#v", got)
	}
	selection, err := ParseToolSelection(`{"tool":"invoice_list","term":"Acme","filters":{"payment":"Unpaid"},"limit":5}`, tools)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Term != "Acme" || selection.Filters["payment"] != "open" {
		t.Fatalf("reviewed filter did not map to database value: %#v", selection)
	}
	for _, raw := range []string{`{"tool":"invoice_list","term":"Acme","filters":{"payment":"pending"},"limit":5}`, `{"tool":"invoice_list","term":"Acme","filters":{"payment":"Unpaid","payment":"Paid"},"limit":5}`, `{"tool":"invoice_list","term":"Acme","limit":5}`} {
		if _, err := ParseToolSelection(raw, tools); err == nil {
			t.Errorf("unsafe or incomplete related selection accepted: %s", raw)
		}
	}
	if _, err := ParseToolSelection(`{"tool":null,"limit":0,"filters":{}}`, tools); err == nil {
		t.Fatal("no-tool selection accepted filter data")
	}
}

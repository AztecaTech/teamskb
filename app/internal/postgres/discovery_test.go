package postgres

import (
	"fmt"
	"testing"
)

func TestDiscoveryCursorContinuesAfterLastReturnedRelation(t *testing.T) {
	all := make([]DiscoveredRelation, 202)
	for i := range all {
		all[i] = DiscoveredRelation{Schema: "s", Name: fmt.Sprintf("t%03d", i)}
	}
	var seen []string
	for start := 0; start < len(all); {
		end := start + maxDiscoveryRelations
		if end > len(all) {
			end = len(all)
		}
		page := all[start:end]
		seen = append(seen, pageNames(page)...)
		if end == len(all) {
			break
		}
		schema, name := nextRelationCursor(page)
		start = end
		if all[start].Schema < schema || all[start].Schema == schema && all[start].Name <= name {
			t.Fatal("cursor would skip or repeat the next relation")
		}
	}
	if len(seen) != len(all) || seen[100] != "t100" || seen[201] != "t201" {
		t.Fatalf("paging lost relation(s): count=%d", len(seen))
	}
}

func pageNames(relations []DiscoveredRelation) []string {
	names := make([]string, len(relations))
	for i, relation := range relations {
		names[i] = relation.Name
	}
	return names
}

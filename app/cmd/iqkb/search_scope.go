package main

import "context"

type searchScopeKey struct{}
type databaseSelectionStatusKey struct{}

func searchScope(ctx context.Context) string {
	if scope, ok := ctx.Value(searchScopeKey{}).(string); ok {
		return scope
	}
	return "all"
}
func scopeIncludes(scope string, index int) bool {
	if index == 5 {
		return scope != "microsoft"
	}
	return scope != "database"
}

type sourceSearchStatus struct {
	Source  string `json:"source"`
	Status  string `json:"status"`
	Results int    `json:"results"`
}

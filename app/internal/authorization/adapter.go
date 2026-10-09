// Package authorization defines source-independent read authorization. Identity
// and configuration are established by the server, never by the model.
package authorization

import (
	"context"
	"errors"
	"strings"
)

var ErrDenied = errors.New("resource_read_denied")

type Identity struct {
	ID, Email, TenantID, Label, Revision string
	Claims                               map[string]string
	DatabasePolicyVerified               bool
}
type Resource struct {
	Namespace, Name string
	Fields          []string
}
type Membership struct {
	Schema       string `json:"schema"`
	Relation     string `json:"relation"`
	UserColumn   string `json:"userColumn"`
	GroupColumn  string `json:"groupColumn"`
	ActiveColumn string `json:"activeColumn,omitempty"`
	TenantColumn string `json:"tenantColumn,omitempty"`
}
type Scope struct {
	Kind       string      `json:"kind"`
	Column     string      `json:"column,omitempty"`
	Claim      string      `json:"claim,omitempty"`
	Membership *Membership `json:"membership,omitempty"`
}
type Rule struct {
	Label    string   `json:"label"`
	Schema   string   `json:"schema"`
	Relation string   `json:"relation"`
	Fields   []string `json:"fields"`
	Scope    Scope    `json:"scope"`
	Reviewed bool     `json:"reviewed"`
}
type Decision struct {
	Fields    []string
	Scope     Scope
	Delegated bool
}
type Adapter interface {
	Authorize(context.Context, Identity, Resource) (Decision, error)
}
type Factory func([]Rule) (Adapter, error)

// A registry permits additional reviewed providers without changing callers.
// Registration is server code; arbitrary browser/model code cannot be loaded.
type Registry struct{ factories map[string]Factory }

func NewRegistry() *Registry {
	r := &Registry{factories: map[string]Factory{}}
	r.factories["application_rules"] = func(rules []Rule) (Adapter, error) {
		if err := ValidateRules(rules); err != nil {
			return nil, err
		}
		return ruleAdapter{rules}, nil
	}
	r.factories["database_policy"] = func([]Rule) (Adapter, error) { return databaseAdapter{}, nil }
	return r
}
func (r *Registry) Register(name string, f Factory) error {
	if strings.TrimSpace(name) == "" || f == nil || r.factories[name] != nil {
		return errors.New("invalid or duplicate adapter")
	}
	r.factories[name] = f
	return nil
}
func (r *Registry) Create(name string, rules []Rule) (Adapter, error) {
	f := r.factories[name]
	if f == nil {
		return nil, errors.New("authorization_adapter_unsupported")
	}
	return f(rules)
}

func ValidateRules(rules []Rule) error {
	if len(rules) > 100 {
		return errors.New("too many resource rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		key := r.Label + "\x00" + r.Schema + "\x00" + r.Relation
		if strings.TrimSpace(r.Label) == "" || len(r.Label) > 256 || r.Schema == "" || r.Relation == "" || seen[key] || len(r.Fields) > 32 {
			return errors.New("invalid or duplicate resource rule")
		}
		seen[key] = true
		fields := map[string]bool{}
		for _, f := range r.Fields {
			if f == "" || fields[f] {
				return errors.New("invalid readable field")
			}
			fields[f] = true
		}
		switch r.Scope.Kind {
		case "pending":
			if r.Reviewed {
				return errors.New("unresolved scope cannot be reviewed")
			}
		case "all":
			if r.Scope.Column != "" || r.Scope.Claim != "" || r.Scope.Membership != nil {
				return errors.New("all-row scope cannot contain other conditions")
			}
		case "user", "email", "claim", "membership":
			if r.Scope.Column == "" {
				return errors.New("scoped rule requires a column")
			}
			if (r.Scope.Kind == "claim") != (r.Scope.Claim != "") || (r.Scope.Kind == "membership") != (r.Scope.Membership != nil) {
				return errors.New("incompatible scope configuration")
			}
			if m := r.Scope.Membership; m != nil && (m.Schema == "" || m.Relation == "" || m.UserColumn == "" || m.GroupColumn == "") {
				return errors.New("incomplete membership mapping")
			}
		default:
			return errors.New("unsupported permission scope")
		}
		if r.Reviewed && len(r.Fields) == 0 {
			return errors.New("reviewed rule has no readable fields")
		}
	}
	return nil
}

type ruleAdapter struct{ rules []Rule }

func (a ruleAdapter) Authorize(ctx context.Context, id Identity, res Resource) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if id.ID == "" || id.Email == "" || id.TenantID == "" || id.Revision == "" {
		return Decision{}, ErrDenied
	}
	for _, r := range a.rules {
		if r.Label != id.Label || r.Schema != res.Namespace || r.Relation != res.Name || !r.Reviewed || r.Scope.Kind == "pending" {
			continue
		}
		allowed := map[string]bool{}
		for _, f := range r.Fields {
			allowed[f] = true
		}
		for _, f := range res.Fields {
			if !allowed[f] {
				return Decision{}, ErrDenied
			}
		}
		if r.Scope.Kind == "claim" && id.Claims[r.Scope.Claim] == "" {
			return Decision{}, ErrDenied
		}
		return Decision{Fields: append([]string(nil), r.Fields...), Scope: r.Scope}, nil
	}
	return Decision{}, ErrDenied
}

type databaseAdapter struct{}

func (databaseAdapter) Authorize(ctx context.Context, id Identity, res Resource) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if !id.DatabasePolicyVerified {
		return Decision{}, ErrDenied
	}
	return Decision{Fields: res.Fields, Delegated: true}, nil
}

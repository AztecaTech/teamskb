package postgres

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

var toolIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

type ToolSelection struct {
	ToolID  string
	Limit   int
	Term    string
	Filters map[string]string
}

type toolChoice struct {
	Tool    *string           `json:"tool"`
	Limit   int               `json:"limit"`
	Term    string            `json:"term,omitempty"`
	Filters map[string]string `json:"filters,omitempty"`
}

func SelectionPrompt(question string, tools []QueryTool) (string, error) {
	tools = FilterProfileReferences(tools)
	choices := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		if err := ValidateQueryTool(tool); err != nil {
			return "", err
		}
		choice := map[string]any{
			"id": tool.ID, "description": tool.Description,
			"parameters": []string{"question:text (bound by the application)", "limit:integer[1,5]"},
		}
		if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" {
			var profile BusinessProfile
			if err := json.Unmarshal(tool.ProfileConfig, &profile); err != nil {
				return "", errors.New("invalid approved PostgreSQL profile")
			}
			choice["businessLabel"], choice["synonyms"], choice["capability"] = profile.Label, profile.Synonyms, profile.Capability
			if profile.Capability == "text_search" {
				choice["searchStrategy"], choice["language"] = profile.SearchStrategy, profile.Language
			}
			if profile.Capability == "related_list" {
				for _, parentTool := range tools {
					if parentTool.ID != profile.Relationship.ParentProfileID {
						continue
					}
					var parent BusinessProfile
					if json.Unmarshal(parentTool.ProfileConfig, &parent) == nil && parent.Capability == "entity_lookup" {
						choice["parentEntityLabel"], choice["parentEntitySynonyms"] = parent.Label, parent.Synonyms
					}
				}
				parameters := []string{"term:text (the parent entity name or identifier)"}
				for _, filter := range profile.Relationship.Filters {
					labels := make([]string, 0, len(filter.Values))
					for _, value := range filter.Values {
						labels = append(labels, value.Label)
					}
					choice["filter_"+filter.Name] = labels
					requirement := "optional"
					if filter.Required {
						requirement = "required"
					}
					parameters = append(parameters, "filters."+filter.Name+":enum["+strings.Join(labels, ",")+"] ("+requirement+")")
				}
				parameters = append(parameters, "limit:integer[1,5]")
				choice["parameters"] = parameters
			} else {
				choice["parameters"] = []string{"term:text (select the specific entity or search phrase)", "limit:integer[1,5]"}
			}
		}
		choices = append(choices, choice)
	}
	request, err := json.Marshal(map[string]any{"question": question, "approvedTools": choices})
	if err != nil {
		return "", err
	}
	return string(request), nil
}

func ParseToolSelection(raw string, tools []QueryTool) (*ToolSelection, error) {
	tools = FilterProfileReferences(tools)
	fields, err := decodeUniqueObject(raw)
	if err != nil {
		return nil, err
	}
	if len(fields) < 2 || len(fields) > 4 || fields["tool"] == nil || fields["limit"] == nil {
		return nil, errors.New("selection must contain an approved tool, limit, and optional profile term")
	}
	var choice toolChoice
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&choice); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("selection contains trailing data")
	}
	if choice.Tool == nil {
		if choice.Limit != 0 || choice.Term != "" || fields["term"] != nil || fields["filters"] != nil || len(choice.Filters) > 0 {
			return nil, errors.New("no-tool selection must not include a limit")
		}
		return nil, nil
	}
	if choice.Limit < 1 || choice.Limit > maxResults {
		return nil, errors.New("selected query limit is outside the approved range")
	}
	for _, tool := range tools {
		if tool.ID == *choice.Tool {
			selection := &ToolSelection{ToolID: tool.ID, Limit: choice.Limit}
			if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" {
				if fields["term"] == nil {
					return nil, errors.New("profile selection requires a search term")
				}
				if !validQuestion(choice.Term) {
					return nil, errors.New("profile selection requires a bounded search term")
				}
				selection.Term = choice.Term
				var profile BusinessProfile
				if err := json.Unmarshal(tool.ProfileConfig, &profile); err != nil {
					return nil, errors.New("invalid approved PostgreSQL profile")
				}
				if profile.Capability == "related_list" {
					if fields["filters"] != nil {
						filterFields, err := decodeUniqueObject(string(fields["filters"]))
						if err != nil {
							return nil, errors.New("invalid related-list filters")
						}
						if len(filterFields) != len(choice.Filters) {
							return nil, errors.New("related-list filter selection is incomplete")
						}
					}
					selection.Filters = make(map[string]string, len(choice.Filters))
					for _, filter := range profile.Relationship.Filters {
						if filter.Required {
							if _, ok := choice.Filters[filter.Name]; !ok {
								return nil, errors.New("required related-list filter is missing")
							}
						}
					}
					for name, label := range choice.Filters {
						var configured *ProfileFilter
						for i := range profile.Relationship.Filters {
							if profile.Relationship.Filters[i].Name == name {
								configured = &profile.Relationship.Filters[i]
								break
							}
						}
						if configured == nil {
							return nil, errors.New("selected filter is not approved")
						}
						var canonical string
						foundValue := false
						for _, value := range configured.Values {
							if strings.EqualFold(value.Label, label) {
								canonical = value.Value
								foundValue = true
								break
							}
						}
						if !foundValue {
							return nil, errors.New("selected filter value is not approved")
						}
						selection.Filters[name] = canonical
					}
					if len(selection.Filters) != len(choice.Filters) {
						return nil, errors.New("unexpected related-list filters")
					}
				} else if fields["filters"] != nil || len(choice.Filters) > 0 {
					return nil, errors.New("filters are not approved for this profile")
				}
			} else if fields["term"] != nil {
				return nil, errors.New("legacy query selection cannot include a profile term")
			}
			return selection, nil
		}
	}
	return nil, errors.New("selected query tool is not approved")
}

func decodeUniqueObject(raw string) (map[string]json.RawMessage, error) {
	if len(raw) > 4096 {
		return nil, errors.New("selection is too large")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, errors.New("selection must be a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("selection key is invalid")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("selection contains a duplicate field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if closing != json.Delim('}') {
		return nil, errors.New("selection object is malformed")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("selection contains trailing data")
	}
	return fields, nil
}

func ValidateQueryTool(tool QueryTool) error {
	if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" {
		var profile BusinessProfile
		if err := json.Unmarshal(tool.ProfileConfig, &profile); err != nil || ValidateBusinessProfile(profile) != nil || len(profile.SchemaFingerprint) != 64 || profile.ID != tool.ID || profile.Version != tool.Version {
			return errors.New("invalid approved PostgreSQL profile")
		}
		canonical, err := CompileBusinessProfile(profile)
		if err != nil || canonical != tool.SQL {
			return errors.New("PostgreSQL profile SQL is not canonical")
		}
		wantParams := ProfileParameters(profile)
		if len(tool.Parameters) != len(wantParams) {
			return errors.New("profile parameters do not match the approved schema")
		}
		for i := range wantParams {
			if tool.Parameters[i] != wantParams[i] {
				return errors.New("profile parameters do not match the approved schema")
			}
		}
		want := ProfileOutputColumns(profile)
		if len(want) != len(tool.OutputColumns) {
			return errors.New("profile output schema is invalid")
		}
		for i := range want {
			if want[i] != tool.OutputColumns[i] {
				return errors.New("profile output schema is invalid")
			}
		}
		return nil
	}
	if !toolIDPattern.MatchString(tool.ID) || tool.Version < 1 || tool.Version > 1_000_000 ||
		strings.TrimSpace(tool.Description) == "" || len(tool.Description) > 512 ||
		strings.TrimSpace(tool.ApprovalRecord) == "" || len(tool.ApprovalRecord) > 256 || !isApprovedSelect(tool.SQL) {
		return errors.New("invalid approved PostgreSQL query")
	}
	if len(tool.Parameters) != 2 || tool.Parameters[0] != (QueryParameter{Name: "question", Type: "text"}) ||
		tool.Parameters[1] != (QueryParameter{Name: "limit", Type: "integer[1,5]"}) {
		return errors.New("PostgreSQL query parameters must be question:text and limit:integer[1,5]")
	}
	want := []string{"id:text", "title:text", "content:text", "source_url:text"}
	if len(tool.OutputColumns) != len(want) {
		return errors.New("PostgreSQL query must return id, title, content, and source_url text columns")
	}
	for i := range want {
		if tool.OutputColumns[i] != want[i] {
			return errors.New("PostgreSQL query output schema is not approved")
		}
	}
	return nil
}

func isApprovedSelect(query string) bool {
	if len(query) == 0 || len(query) > 16*1024 || strings.TrimSpace(query) != query {
		return false
	}
	const (
		normal = iota
		singleQuoted
		doubleQuoted
	)
	state, firstWord, nextParam := normal, true, 1
	word := strings.Builder{}
	quotedIdentifier := strings.Builder{}
	flush := func() bool {
		if word.Len() == 0 {
			return true
		}
		value := word.String()
		word.Reset()
		if firstWord {
			firstWord = false
			return value == "SELECT"
		}
		switch value {
		case "INTO", "INSERT", "UPDATE", "DELETE", "MERGE", "CALL", "DO", "COPY", "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "TRUNCATE", "EXECUTE", "RESET", "SET_CONFIG":
			return false
		}
		return !isForbiddenSQLFunction(value)
	}
	for i := 0; i < len(query); i++ {
		ch := query[i]
		switch state {
		case singleQuoted:
			if ch == '\'' {
				if i+1 < len(query) && query[i+1] == '\'' {
					i++
				} else {
					state = normal
				}
			}
		case doubleQuoted:
			if ch == '"' {
				if i+1 < len(query) && query[i+1] == '"' {
					quotedIdentifier.WriteByte('"')
					i++
				} else {
					if isForbiddenSQLFunction(strings.ToUpper(quotedIdentifier.String())) {
						return false
					}
					quotedIdentifier.Reset()
					state = normal
				}
			} else {
				quotedIdentifier.WriteByte(ch)
			}
		default:
			switch {
			case ch == '\'':
				if !flush() {
					return false
				}
				state = singleQuoted
			case ch == '"':
				if !flush() {
					return false
				}
				quotedIdentifier.Reset()
				state = doubleQuoted
			case ch == '-' && i+1 < len(query) && query[i+1] == '-' || ch == '/' && i+1 < len(query) && query[i+1] == '*':
				return false
			case ch == ';' || ch == '$' && (i+1 >= len(query) || query[i+1] < '0' || query[i+1] > '9'):
				return false
			case (ch == 'U' || ch == 'u') && i+2 < len(query) && query[i+1] == '&' && query[i+2] == '"':
				return false
			case ch == '$':
				if !flush() {
					return false
				}
				j := i + 1
				for j < len(query) && query[j] >= '0' && query[j] <= '9' {
					j++
				}
				if j == i+1 || query[i+1:j] != string(rune('0'+nextParam)) {
					return false
				}
				nextParam++
				i = j - 1
			case isSQLWord(ch):
				word.WriteByte(toUpperASCII(ch))
			default:
				if !flush() {
					return false
				}
			}
		}
	}
	if state != normal || !flush() || firstWord || nextParam != 3 {
		return false
	}
	return true
}

func isForbiddenSQLFunction(name string) bool {
	switch name {
	case "SET_CONFIG", "PG_READ_FILE", "PG_READ_BINARY_FILE", "PG_WRITE_FILE", "PG_LS_DIR", "PG_STAT_FILE", "DBLINK", "DBLINK_EXEC", "LO_IMPORT", "LO_EXPORT", "PG_NOTIFY", "PG_ADVISORY_LOCK", "PG_ADVISORY_LOCK_SHARED", "PG_TRY_ADVISORY_LOCK", "PG_TRY_ADVISORY_LOCK_SHARED", "PG_ADVISORY_XACT_LOCK", "PG_ADVISORY_XACT_LOCK_SHARED", "PG_TRY_ADVISORY_XACT_LOCK", "PG_TRY_ADVISORY_XACT_LOCK_SHARED", "NEXTVAL", "SETVAL":
		return true
	default:
		return false
	}
}

func isSQLWord(ch byte) bool {
	return ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func toUpperASCII(ch byte) byte {
	if ch >= 'a' && ch <= 'z' {
		return ch - ('a' - 'A')
	}
	return ch
}

func Catalog(db *sql.DB) ([]QueryTool, error) {
	rows, err := db.Query(`SELECT tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config FROM query_tools ORDER BY tool_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tools := make([]QueryTool, 0)
	for rows.Next() {
		var tool QueryTool
		var params, outputs, profileConfig []byte
		if err := rows.Scan(&tool.ID, &tool.Version, &tool.Description, &tool.SQL, &params, &outputs, &tool.ApprovalRecord, &profileConfig); err != nil {
			return nil, err
		}
		tool.ProfileConfig = profileConfig
		if err := json.Unmarshal(params, &tool.Parameters); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(outputs, &tool.OutputColumns); err != nil {
			return nil, err
		}
		if err := ValidateQueryTool(tool); err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return FilterProfileReferences(tools), nil
}

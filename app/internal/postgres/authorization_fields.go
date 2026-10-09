package postgres

import "strings"

// Credential fields are excluded from the administrator's resource catalog.
func SensitiveAuthorizationField(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", ""))
	for _, signal := range []string{"password", "secret", "token", "backupcode"} {
		if strings.Contains(normalized, signal) {
			return true
		}
	}
	return false
}

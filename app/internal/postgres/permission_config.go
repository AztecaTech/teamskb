package postgres

const (
	InternalPermissionSource = "internal"
	ExternalPermissionSource = "external"
)

// PermissionLocation keeps older saved configurations on the internal adapter.
// The persisted JSON field is intentionally unchanged.
func (a AdapterConfig) PermissionLocation() string {
	if a.PermissionSource == "" {
		return InternalPermissionSource
	}
	return a.PermissionSource
}

func (a AdapterConfig) UsesExternalPermissions() bool {
	return a.Mode == "application_rules" && a.PermissionLocation() == ExternalPermissionSource
}

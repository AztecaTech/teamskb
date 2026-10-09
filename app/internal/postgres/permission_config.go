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

// Table access is defined here by an administrator. A current user's successful
// profile check validates this policy; advanced native/scoped adapters retain
// their independent two-user verification requirement.
func (a AdapterConfig) RequiredProfileTestUsers() int {
	if a.RoleLabelAccess && a.Validate() == nil {
		return 1
	}
	return 2
}

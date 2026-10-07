package postgres

import "context"

// CheckToolAccess checks privileges and result types without scanning data. The
// actual selected query still runs with freshly resolved user permissions.
func (c *Connector) CheckToolAccess(ctx context.Context, login, password string, tool QueryTool) error {
	if err := ValidateQueryTool(tool); err != nil {
		return err
	}
	conn, tx, _, err := c.beginAuthorized(ctx, login, password)
	if err != nil {
		return err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT * FROM (`+tool.SQL+`) AS iqkb_access_check LIMIT 0`, "", 1)
	if err != nil {
		return err
	}
	defer rows.Close()
	if err := validateOutputSchema(rows.FieldDescriptions()); err != nil {
		return err
	}
	return rows.Err()
}

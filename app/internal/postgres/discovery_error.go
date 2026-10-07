package postgres

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Return actionable categories without exposing DSNs, passwords, SQL, or raw
// server error messages to the browser.
func DiscoveryFailureCode(err error) string {
	if errors.Is(err, ErrUnsafeDatabaseRole) {
		return "unsafe_database_login"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "database_timeout"
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		if strings.HasPrefix(databaseError.Code, "28") {
			return "database_authentication_failed"
		}
		switch databaseError.Code {
		case "3D000":
			return "database_not_found"
		case "42501":
			return "metadata_permission_denied"
		case "57014":
			return "database_timeout"
		}
		return "database_request_failed"
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	if errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &certificate) {
		return "database_tls_verification_failed"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "database_dns_failed"
	}
	var network *net.OpError
	if errors.As(err, &network) {
		return "database_unreachable"
	}
	return "authorization_metadata_discovery_failed"
}

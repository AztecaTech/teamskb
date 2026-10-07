package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Return actionable categories without exposing DSNs, passwords, SQL, or raw
// server error messages to the browser.
func DiscoveryFailureCode(err error) string {
	if errors.Is(err, ErrMetadataIdentityMismatch) {
		return "metadata_identity_mismatch"
	}
	if errors.Is(err, ErrUnsafeDatabaseRole) {
		return "unsafe_database_login"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "database_timeout"
	}
	// pgx returns a plain error for a server rejecting SSL negotiation.
	// Match only the exact driver error; never expose raw connection details.
	if hasDiscoveryCause(err, "server refused TLS connection") {
		return "database_tls_unavailable"
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "database_tls_handshake_failed"
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
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "database_connection_closed"
	}
	return "authorization_metadata_discovery_failed"
}

func hasDiscoveryCause(err error, message string) bool {
	if err == nil {
		return false
	}
	if err.Error() == message {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if hasDiscoveryCause(cause, message) {
				return true
			}
		}
		return false
	}
	return hasDiscoveryCause(errors.Unwrap(err), message)
}

package postgres

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestDiscoveryFailureCodesPreserveWrappedConnectionCauses(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{ErrUnsafeDatabaseRole, "unsafe_database_login"},
		{&pgconn.PgError{Code: "28P01", Message: "private password detail"}, "database_authentication_failed"},
		{&pgconn.PgError{Code: "42501"}, "metadata_permission_denied"},
		{&pgconn.PgError{Code: "3D000"}, "database_not_found"},
		{&net.DNSError{Err: "private host", Name: "private host"}, "database_dns_failed"},
		{x509.UnknownAuthorityError{}, "database_tls_verification_failed"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("refused")}, "database_unreachable"},
		{context.DeadlineExceeded, "database_timeout"},
	} {
		if got := DiscoveryFailureCode(fmt.Errorf("discovery: %w", test.err)); got != test.want {
			t.Errorf("code=%s want=%s", got, test.want)
		}
	}
}

package postgres

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
		{errors.New("server refused TLS connection"), "database_tls_unavailable"},
		{io.EOF, "database_connection_closed"},
	} {
		if got := DiscoveryFailureCode(fmt.Errorf("discovery: %w", test.err)); got != test.want {
			t.Errorf("code=%s want=%s", got, test.want)
		}
	}
}

func TestAuthorizationDiscoveryDiagnosesServerWithoutTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var request [8]byte
		if _, err = io.ReadFull(conn, request[:]); err == nil {
			if binary.BigEndian.Uint32(request[4:]) != 80877103 {
				err = errors.New("expected PostgreSQL SSL request")
			} else {
				_, err = conn.Write([]byte{'N'})
			}
		}
		done <- err
	}()
	connector, err := Open(t.Context(), "postgres://service:secret@"+listener.Addr().String()+"/test?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	_, err = connector.DiscoverAuthorization(t.Context(), "", "")
	if DiscoveryFailureCode(err) != "database_tls_unavailable" || DiscoveryFailureStage(err) != "connection" {
		t.Fatalf("unexpected diagnostic: code=%s stage=%s", DiscoveryFailureCode(err), DiscoveryFailureStage(err))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

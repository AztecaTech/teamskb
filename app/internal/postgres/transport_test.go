package postgres

import (
	"errors"
	"net"
	"testing"
)

func TestPrivateTransportRequiresExplicitMode(t *testing.T) {
	dsn := "postgres://service:secret@localhost/db?sslmode=disable"
	if _, err := Open(t.Context(), dsn); err == nil {
		t.Fatal("plaintext accepted by default")
	}
	if _, err := OpenWithMode(t.Context(), dsn, "private_network"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithMode(t.Context(), "postgres://localhost/db?sslmode=prefer", "private_network"); err == nil {
		t.Fatal("automatic TLS fallback accepted")
	}
	if _, err := OpenWithMode(t.Context(), dsn, "typo"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestPrivateTransportRejectsPublicAndLinkLocalAddresses(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:5432", "169.254.169.254:5432", "[2001:4860:4860::8888]:5432", "[fe80::1]:5432"} {
		if _, err := dialPrivatePostgres(t.Context(), "tcp", addr); !errors.Is(err, ErrPrivateDatabaseEndpoint) {
			t.Fatalf("%s: public destination not rejected", addr)
		}
	}
}

func TestPrivateTransportConnectsToLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := dialPrivatePostgres(t.Context(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

package postgres

import (
	"context"
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

func TestExternalPlaintextAcceptsPublicURIWithoutPrivateDialRestriction(t *testing.T) {
	connector, err := OpenWithMode(t.Context(), "postgres://service:secret@203.0.113.10:15432/db?sslmode=disable", "external_plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if connector.service.Host != "203.0.113.10" || connector.service.Port != 15432 || connector.service.TLSConfig != nil {
		t.Fatal("external endpoint or plaintext configuration changed")
	}
	// A normal TCP dial should reach the OS dialer, rather than being rejected
	// by private-network address validation. Use an already-cancelled context.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := connector.service.DialFunc(ctx, "tcp", "203.0.113.10:15432"); errors.Is(err, ErrPrivateDatabaseEndpoint) {
		t.Fatal("external mode retained the private-address restriction")
	}
	for _, sslmode := range []string{"prefer", "require", "verify-full"} {
		if _, err := OpenWithMode(t.Context(), "postgres://localhost/db?sslmode="+sslmode, "external_plaintext"); err == nil {
			t.Fatalf("ambiguous external plaintext configuration accepted: %s", sslmode)
		}
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

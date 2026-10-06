package identity

import (
	"strings"
	"testing"
)

func TestVerifierAllowsOnlyMicrosoftClientsAndExplicitOAuthClients(t *testing.T) {
	const configured = "12345678-1234-4234-9234-123456789abc"
	verifier, err := NewVerifier("22345678-1234-4234-9234-123456789abc", "32345678-1234-4234-9234-123456789abc", configured)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.authorizedClient(strings.ToLower(configured)) {
		t.Fatal("configured OAuth client was not accepted")
	}
	if !verifier.authorizedClient("1fec8e78-bce4-4aaf-ab1b-5451cc387264") {
		t.Fatal("documented Teams first-party client was not accepted")
	}
	if verifier.authorizedClient("42345678-1234-4234-9234-123456789abc") {
		t.Fatal("unconfigured client was accepted")
	}
}

func TestVerifierRejectsMalformedAdditionalClient(t *testing.T) {
	if _, err := NewVerifier("22345678-1234-4234-9234-123456789abc", "32345678-1234-4234-9234-123456789abc", "not-a-guid"); err == nil {
		t.Fatal("malformed additional client ID was accepted")
	}
}

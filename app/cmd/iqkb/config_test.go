package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadSecretFromEnvironmentAndMountedFile(t *testing.T) {
	t.Setenv("IQKB_TEST_MODEL_KEY", "environment-key-123")
	if value, err := readSecret("", "IQKB_TEST_MODEL_KEY"); err != nil || value != "environment-key-123" {
		t.Fatalf("environment secret=%q err=%v", value, err)
	}
	path := filepath.Join(t.TempDir(), "model-key")
	if err := os.WriteFile(path, []byte("mounted-file-key-456\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := readSecret(path, "IQKB_TEST_MODEL_KEY"); err != nil || value != "mounted-file-key-456" {
		t.Fatalf("mounted secret=%q err=%v", value, err)
	}
	t.Setenv("IQKB_TEST_UNSET_KEY", "")
	if value, err := readSecret("", "IQKB_TEST_UNSET_KEY"); err != nil || value != "" {
		t.Fatalf("unset optional secret=%q err=%v", value, err)
	}
}

func TestPublicServerBoundsRequestAndResponseTime(t *testing.T) {
	server := newPublicHTTPServer(http.NotFoundHandler())
	if server.ReadTimeout <= 0 || server.WriteTimeout <= requestProcessingTimeout {
		t.Fatalf("public HTTP timeouts do not bound uploads and permit ask processing: read=%s write=%s processing=%s", server.ReadTimeout, server.WriteTimeout, requestProcessingTimeout)
	}
}

func TestPublicServerTimesOutTrickledRequestBody(t *testing.T) {
	server := newPublicHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "request body timed out", http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.ReadTimeout = 250 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("server did not return a timeout response: %v", err)
	}
	if !strings.Contains(status, "408 Request Timeout") {
		t.Fatalf("slow request body returned status %q, want 408", strings.TrimSpace(status))
	}
}

func TestReadKeyFromEnvironmentAndMountedFile(t *testing.T) {
	expected := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("IQKB_TEST_ENCRYPTION_KEY", expected)
	if value, err := readKey("", "IQKB_TEST_ENCRYPTION_KEY"); err != nil || hex.EncodeToString(value) != expected {
		t.Fatalf("environment key=%x err=%v", value, err)
	}
	path := filepath.Join(t.TempDir(), "encryption-key")
	if err := os.WriteFile(path, []byte(expected+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := readKey(path, "IQKB_TEST_ENCRYPTION_KEY"); err != nil || hex.EncodeToString(value) != expected {
		t.Fatalf("mounted key=%x err=%v", value, err)
	}
}

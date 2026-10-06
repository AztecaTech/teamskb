package answer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOpenAICompatibleRequestIsStatelessAndGrounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer model-key" {
			t.Errorf("unexpected request: path=%s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if bytes.Contains(body, []byte("model-key")) {
			t.Error("API key must not appear in the request body")
		}
		var request struct {
			Store    *bool             `json:"store"`
			Tools    []json.RawMessage `json:"tools"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
		}
		if request.Store == nil || *request.Store {
			t.Error("request must explicitly disable provider storage")
		}
		if len(request.Tools) != 0 {
			t.Errorf("answer request must not expose model tools: %s", request.Tools)
		}
		if len(request.Messages) != 2 || request.Messages[0].Role != "system" || !strings.Contains(request.Messages[0].Content, "untrusted reference data") || !strings.Contains(request.Messages[1].Content, "[S1]") {
			t.Errorf("grounding instructions or excerpts missing: %#v", request.Messages)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"test","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"A supported response [S1]."},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}}`))
	}))
	defer server.Close()

	response, err := Generate(context.Background(), "openai_compatible", "test-model", server.URL+"/v1", "model-key", "Question and [S1] source excerpt")
	if err != nil || response != "A supported response [S1]." {
		t.Fatalf("response=%q err=%v", response, err)
	}
}

func TestProviderErrorsAreGeneric(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private provider response", http.StatusInternalServerError)
	}))
	defer server.Close()
	response, err := Generate(context.Background(), "openai_compatible", "test-model", server.URL+"/v1", "model-key", "Question")
	if err == nil || response != "" || strings.Contains(err.Error(), "private provider response") {
		t.Fatalf("provider error leaked: response=%q err=%v", response, err)
	}
}

func TestOpenAICompatibleProviderRedirectsAreNotFollowed(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var destinationCalls atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				destinationCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer destination.Close()

			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Redirect(w, nil, destination.URL+"/capture", status)
			}))
			defer provider.Close()

			if _, err := Generate(context.Background(), "openai_compatible", "test-model", provider.URL+"/v1", "model-key", "synthetic evidence [S1]"); err == nil {
				t.Fatal("redirect response should fail the provider request")
			}
			if got := destinationCalls.Load(); got != 0 {
				t.Fatalf("redirect destination received %d requests", got)
			}
		})
	}
}

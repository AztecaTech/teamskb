package parserclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxDocumentBytes = 24 << 20

type requestPayload struct {
	Filename      string `json:"filename"`
	ContentBase64 string `json:"contentBase64"`
}

type responsePayload struct {
	Text  string `json:"text"`
	Error string `json:"error"`
}

func Extract(ctx context.Context, socketPath, filename string, content []byte) (string, error) {
	if len(content) == 0 || len(content) > maxDocumentBytes || len(filename) > 255 || strings.TrimSpace(filename) == "" {
		return "", errors.New("document exceeds parser limits")
	}
	data, err := json.Marshal(requestPayload{Filename: filename, ContentBase64: base64.StdEncoding.EncodeToString(content)})
	if err != nil {
		return "", err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 35 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://parser/v1/parse", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 3<<20+1))
	if err != nil || len(body) > 3<<20 {
		return "", errors.New("parser response limit exceeded")
	}
	var parsed responsePayload
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", errors.New("invalid parser response")
	}
	if response.StatusCode != http.StatusOK {
		return "", errors.New(parsed.Error)
	}
	return parsed.Text, nil
}

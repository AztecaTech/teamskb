package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func DecodeOne[T any](body []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return value, errors.New("request must contain exactly one JSON value")
		}
		return value, err
	}
	return value, nil
}

package graph

import (
	"errors"
	"fmt"
)

// Diagnostics expose operation names and status codes, never Graph response
// bodies, tokens, tenant IDs, team IDs, or source content.
type GraphHTTPError struct{ Status int }

func (e *GraphHTTPError) Error() string {
	return fmt.Sprintf("Graph request returned status %d", e.Status)
}

type ChannelCheckError struct {
	Stage      string
	HTTPStatus int
	cause      error
}

func (e *ChannelCheckError) Error() string { return e.cause.Error() }
func (e *ChannelCheckError) Unwrap() error { return e.cause }
func channelCheckFailure(stage string, err error) error {
	detail := &ChannelCheckError{Stage: stage, cause: err}
	var upstream *GraphHTTPError
	if errors.As(err, &upstream) {
		detail.HTTPStatus = upstream.Status
	}
	return detail
}

package sfos

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError is a non-2xx response from the firewall.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	// ErrorCode is the machine readable error, e.g. "badRequest" or "resourceConflict".
	ErrorCode string `json:"error"`
	Message   string `json:"message"`
	Code      string `json:"code"`
	// Body holds the raw response when it could not be decoded.
	Body string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.ErrorCode != "" {
		fmt.Fprintf(&b, " %s", e.ErrorCode)
	}
	if e.Code != "" {
		fmt.Fprintf(&b, " (%s)", e.Code)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	} else if e.Body != "" {
		fmt.Fprintf(&b, ": %s", e.Body)
	}
	return b.String()
}

func newAPIError(method, path string, status int, body []byte) error {
	e := &APIError{Method: method, Path: path, StatusCode: status}
	if err := json.Unmarshal(body, e); err != nil || (e.ErrorCode == "" && e.Message == "") {
		e.Body = strings.TrimSpace(string(body))
	}
	return e
}

// IsNotFound reports whether err is an HTTP 404 from the API.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

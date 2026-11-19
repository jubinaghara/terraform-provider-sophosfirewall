// Package sfos is a small HTTP client for the Sophos Firewall (SFOS)
// Configuration REST API (https://<host>:<port>/api/firewall-config/v1).
package sfos

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// BasePath is the path prefix of the configuration API on the firewall.
const BasePath = "/api/firewall-config/v1"

// Config holds the settings used to build a Client.
type Config struct {
	// Endpoint is the firewall address. Accepted forms: "host:port",
	// "https://host:port" or a full base URL including BasePath.
	Endpoint string
	// APIKey is sent as a bearer token.
	APIKey string
	// Insecure skips TLS certificate verification (self-signed appliances).
	Insecure bool
	// Timeout bounds every individual HTTP request.
	Timeout time.Duration
	// MaxRetries is the number of retries for throttled or unavailable responses.
	MaxRetries int
	// UserAgent identifies the caller.
	UserAgent string
}

// Client talks to a single firewall. It is safe for concurrent use.
type Client struct {
	baseURL    string
	apiKey     string
	userAgent  string
	maxRetries int
	http       *http.Client

	// writeMu serialises mutating requests. The firewall applies
	// configuration changes one at a time, and rule positioning in
	// particular is order dependent.
	writeMu sync.Mutex
}

// NewClient validates cfg and returns a ready-to-use Client.
func NewClient(cfg Config) (*Client, error) {
	base, err := NormalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey == "" {
		return nil, errors.New("an API key is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec // explicitly requested by the user for self-signed appliances
	}

	return &Client{
		baseURL:    base,
		apiKey:     cfg.APIKey,
		userAgent:  cfg.UserAgent,
		maxRetries: cfg.MaxRetries,
		http:       &http.Client{Timeout: cfg.Timeout, Transport: transport},
	}, nil
}

// NormalizeEndpoint turns the user supplied endpoint into the API base URL.
func NormalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("an endpoint is required")
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid endpoint %q: missing host", endpoint)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = BasePath
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// ItemPath returns the path of a single object in a collection.
func ItemPath(collection, idOrName string) string {
	return strings.TrimRight(collection, "/") + "/" + url.PathEscape(idOrName)
}

// Get fetches path and decodes the response into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Post sends body to path and decodes the response into out (may be nil).
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPost, path, body, out)
}

// Patch sends a JSON merge patch to path and decodes the response into out (may be nil).
func (c *Client) Patch(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPatch, path, body, out)
}

// Delete removes the object at path.
func (c *Client) Delete(ctx context.Context, path string) error {
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}

// Do performs an API request with retries for transient failures.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
	}

	if method != http.MethodGet {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
	}

	reqURL := c.baseURL + path
	for attempt := 0; ; attempt++ {
		status, respBody, retryAfter, err := c.once(ctx, method, reqURL, payload)

		retryable := (err != nil && method == http.MethodGet) || isRetryableStatus(status)
		if retryable && attempt < c.maxRetries {
			wait := backoff(attempt, retryAfter)
			tflog.Warn(ctx, "SFOS API request failed, retrying", map[string]any{
				"method": method, "path": path, "status": status, "attempt": attempt + 1, "wait": wait.String(),
			})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		if status >= 400 {
			return newAPIError(method, path, status, respBody)
		}
		if out != nil && len(bytes.TrimSpace(respBody)) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
			}
		}
		return nil
	}
}

func (c *Client) once(ctx context.Context, method, reqURL string, payload []byte) (int, []byte, string, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	tflog.Debug(ctx, "SFOS API request", map[string]any{"method": method, "url": reqURL, "body": string(payload)})
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, "", fmt.Errorf("reading response: %w", err)
	}
	tflog.Debug(ctx, "SFOS API response", map[string]any{"method": method, "url": reqURL, "status": resp.StatusCode, "body": string(respBody)})
	return resp.StatusCode, respBody, resp.Header.Get("Retry-After"), nil
}

func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func backoff(attempt int, retryAfter string) time.Duration {
	if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(attempt)), float64(30*time.Second)))
}

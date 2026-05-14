// Package control wraps the pf HTTP control-plane API as a typed Go client.
// All methods talk JSON over net/http; failures surface the HTTP status code
// alongside the response body so the caller can decide whether to retry.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rangaroo/highload-monitor/internal/proto"
)

// Client talks to a pf control plane over HTTP.
type Client struct {
	base string
	hc   *http.Client
}

// New returns a Client pointed at baseURL, e.g. "http://localhost:9100".
func New(baseURL string) *Client {
	return &Client{
		base: baseURL,
		hc:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Health hits GET /v1/health.
func (c *Client) Health(ctx context.Context) error {
	var out proto.HealthResponse
	if err := c.do(ctx, http.MethodGet, proto.PathHealth, nil, &out); err != nil {
		return err
	}
	if out.Status != "ok" {
		return fmt.Errorf("unexpected health status %q", out.Status)
	}
	return nil
}

// Stats hits GET /v1/stats.
func (c *Client) Stats(ctx context.Context) (proto.StatsResponse, error) {
	var out proto.StatsResponse
	err := c.do(ctx, http.MethodGet, proto.PathStats, nil, &out)
	return out, err
}

// DumpEndpoint hits GET /v1/dump-endpoint.
func (c *Client) DumpEndpoint(ctx context.Context) (string, error) {
	var out proto.DumpEndpointResponse
	if err := c.do(ctx, http.MethodGet, proto.PathDumpEndpoint, nil, &out); err != nil {
		return "", err
	}
	return out.Addr, nil
}

// AddFilter registers spec; returns the pf-assigned ID.
func (c *Client) AddFilter(ctx context.Context, spec proto.FilterSpec) (proto.FilterID, error) {
	req := proto.AddFilterRequest{Filter: spec}
	var out proto.AddFilterResponse
	if err := c.do(ctx, http.MethodPost, proto.PathFilters, req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// ListFilters hits GET /v1/filters.
func (c *Client) ListFilters(ctx context.Context) ([]proto.FilterEntry, error) {
	var out proto.FilterListResponse
	if err := c.do(ctx, http.MethodGet, proto.PathFilters, nil, &out); err != nil {
		return nil, err
	}
	return out.Filters, nil
}

// RemoveFilter hits DELETE /v1/filters/{id}.
func (c *Client) RemoveFilter(ctx context.Context, id proto.FilterID) error {
	path, err := url.JoinPath(proto.PathFilters, id)
	if err != nil {
		return fmt.Errorf("join path: %w", err)
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
	}

	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

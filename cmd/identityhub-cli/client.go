package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIError is a non-2xx answer from the server. Message is the user-facing
// {error} sentence; MFARequired marks the step-up hint.
type APIError struct {
	Status      int
	Message     string
	MFARequired bool
}

func (e *APIError) Error() string {
	if e.MFARequired {
		return fmt.Sprintf("%s (admin API keys must be created in the browser from an MFA-verified session)", e.Message)
	}
	return e.Message
}

// Client speaks the IdentityHub JSON API with a Bearer API key.
type Client struct {
	base string
	key  string
	http *http.Client
}

func newClient(server, key string) *Client {
	return &Client{
		base: strings.TrimSuffix(server, "/"),
		key:  key,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// maxBodyBytes caps response bodies (audit CSV excepted via doRaw).
const maxBodyBytes = 8 << 20

// do performs one JSON request and decodes the response body (nil for
// 204 No Content).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (any, error) {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(raw)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Message     string `json:"error"`
			MFARequired bool   `json:"mfa_required"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{Status: resp.StatusCode, Message: e.Message, MFARequired: e.MFARequired}
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// doRaw performs one request and returns the raw body (for CSV export).
func (c *Client) doRaw(ctx context.Context, method, path string, query url.Values) ([]byte, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Message string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{Status: resp.StatusCode, Message: e.Message}
	}
	return raw, nil
}

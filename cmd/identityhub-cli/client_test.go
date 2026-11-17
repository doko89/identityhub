package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientSendsBearerAndDecodes(t *testing.T) {
	var gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		gotCT = req.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"username":"ara"}}`))
	}))
	defer srv.Close()

	c := newClient(srv.URL, "ih_test")
	resp, err := c.do(context.Background(), "POST", "/api/auth/me", nil, map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if gotAuth != "Bearer ih_test" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q", gotCT)
	}
	if obj(resp, "user")["username"] != "ara" {
		t.Fatalf("resp = %v", resp)
	}
}

func TestClientErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
		case "/mfa":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"multi-factor authentication is required for administrators","mfa_required":true}`))
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
		case "/csv":
			w.Write([]byte("a,b\n1,2\n"))
		}
	}))
	defer srv.Close()
	c := newClient(srv.URL, "k")
	ctx := context.Background()

	_, err := c.do(ctx, "GET", "/missing", nil, nil)
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Status != http.StatusNotFound || apiErr.Message != "not found" {
		t.Fatalf("err = %#v", err)
	}
	_, err = c.do(ctx, "GET", "/mfa", nil, nil)
	apiErr, ok = err.(*APIError)
	if !ok || !apiErr.MFARequired || !strings.Contains(apiErr.Error(), "browser") {
		t.Fatalf("mfa err = %#v", err)
	}
	if out, err := c.do(ctx, "DELETE", "/empty", nil, nil); err != nil || out != nil {
		t.Fatalf("204 = %v, %v", out, err)
	}
	raw, err := c.doRaw(ctx, "GET", "/csv", nil)
	if err != nil || string(raw) != "a,b\n1,2\n" {
		t.Fatalf("csv = %q, %v", raw, err)
	}
}

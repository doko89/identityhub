package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAttrsDefsListPrintsTable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/api/admin/user-attrs" {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"defs":[{"key":"dept","type":"string","multi":false}]}`))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	c := newClient(srv.URL, "k")
	if err := attrsCmd(context.Background(), c, &output{w: &buf}, []string{"defs", "list"}); err != nil {
		t.Fatalf("attrs defs list: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "dept") || !strings.Contains(out, "string") {
		t.Fatalf("output = %q", out)
	}
}

func TestAttrsSetBuildsBody(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotMethod, gotPath = req.Method, req.URL.Path
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"attrs":{"dept":"eng","tags":["a","b"]}}`))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	c := newClient(srv.URL, "k")
	err := attrsCmd(context.Background(), c, &output{w: &buf}, []string{
		"set", "--set", "dept=eng", "--set", "tags=a", "--set", "tags=b", "--clear", "gone", "user-1",
	})
	if err != nil {
		t.Fatalf("attrs set: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/admin/users/user-1/attrs" {
		t.Fatalf("request = %s %s", gotMethod, gotPath)
	}
	// Single --set stays a scalar, repeated keys become an array,
	// --clear becomes null.
	if gotBody["dept"] != "eng" {
		t.Fatalf("dept = %v", gotBody["dept"])
	}
	tags, _ := gotBody["tags"].([]any)
	if len(tags) != 2 || tags[0] != "a" || tags[1] != "b" {
		t.Fatalf("tags = %v", gotBody["tags"])
	}
	v, ok := gotBody["gone"]
	if !ok || v != nil {
		t.Fatalf("gone = %v, %v", v, ok)
	}
	if out := buf.String(); !strings.Contains(out, "eng") || !strings.Contains(out, "a, b") {
		t.Fatalf("output = %q", out)
	}
}

func TestAttrsSetRejectsBadInput(t *testing.T) {
	c := newClient("http://127.0.0.1:1", "k")
	var buf bytes.Buffer
	out := &output{w: &buf}
	for name, args := range map[string][]string{
		"no target":      {"set"},
		"no flags":       {"set", "user-1"},
		"bad set":        {"set", "--set", "novalue", "user-1"},
		"set and clear":  {"set", "--set", "a=b", "--clear", "a", "user-1"},
		"unknown action": {"frobnicate"},
	} {
		if err := attrsCmd(context.Background(), c, out, args); err == nil {
			t.Errorf("%s: err = nil, want usage error", name)
		}
	}
}

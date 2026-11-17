package main

import (
	"strings"
	"testing"
)

func TestFormatTable(t *testing.T) {
	got := formatTable(
		[]string{"ID", "NAME"},
		[][]string{{"1", "ara"}, {"22", "bo"}},
	)
	want := "ID  NAME\n1   ara\n22  bo\n"
	if got != want {
		t.Fatalf("table =\n%q\nwant\n%q", got, want)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasSuffix(line, " ") {
			t.Fatalf("trailing whitespace in %q", line)
		}
	}
}

func TestCell(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"x", "x"},
		{true, "true"},
		{float64(42), "42"},
		{float64(1.5), "1.5"},
		{[]any{"a", "b"}, "a, b"},
		{[]any{}, ""},
		{map[string]any{"a": float64(1)}, `{"a":1}`},
	}
	for _, tc := range cases {
		if got := cell(tc.in); got != tc.want {
			t.Errorf("cell(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShortDate(t *testing.T) {
	if got := shortDate("2026-11-17T10:00:00Z"); got != "2026-11-17" {
		t.Fatalf("shortDate = %q", got)
	}
	if got := shortDate("garbage"); got != "garbage" {
		t.Fatalf("shortDate passthrough = %q", got)
	}
	if got := shortDate(nil); got != "" {
		t.Fatalf("shortDate nil = %q", got)
	}
}

func TestOptional(t *testing.T) {
	var o optional
	if o.set {
		t.Fatal("zero optional is set")
	}
	if err := o.Set("true"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := o.optBool()
	if err != nil || !ok || !v {
		t.Fatalf("optBool = %v, %v, %v", v, ok, err)
	}
	var n optional
	if _, ok, _ := n.optBool(); ok {
		t.Fatal("unset optBool reports set")
	}
	_ = n.Set("maybe")
	if _, _, err := n.optBool(); err == nil {
		t.Fatal("bad bool accepted")
	}
	_ = n.Set("12")
	vv, ok, err := n.optInt()
	if err != nil || !ok || vv != 12 {
		t.Fatalf("optInt = %v, %v, %v", vv, ok, err)
	}
}

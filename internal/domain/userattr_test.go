package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestUserAttrDefValidate(t *testing.T) {
	cases := []struct {
		name string
		def  UserAttrDef
		ok   bool
	}{
		{"string", UserAttrDef{Key: "department", Type: UserAttrString}, true},
		{"number multi", UserAttrDef{Key: "level-2", Type: UserAttrNumber, Multi: true}, true},
		{"boolean", UserAttrDef{Key: "vip", Type: UserAttrBoolean}, true},
		{"empty key", UserAttrDef{Key: "", Type: UserAttrString}, false},
		{"uppercase", UserAttrDef{Key: "Department", Type: UserAttrString}, false},
		{"leading digit", UserAttrDef{Key: "2fa", Type: UserAttrString}, false},
		{"space", UserAttrDef{Key: "my attr", Type: UserAttrString}, false},
		{"underscore", UserAttrDef{Key: "my_attr", Type: UserAttrString}, false},
		{"reserved ldap", UserAttrDef{Key: "memberof", Type: UserAttrString}, false},
		{"reserved oidc", UserAttrDef{Key: "sub", Type: UserAttrString}, false},
		{"reserved posix", UserAttrDef{Key: "uidnumber", Type: UserAttrNumber}, false},
		{"reserved saml", UserAttrDef{Key: "groups", Type: UserAttrString}, false},
		{"bad type", UserAttrDef{Key: "dept", Type: "date"}, false},
		{"empty type", UserAttrDef{Key: "dept"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.def.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrValidation) {
				t.Fatalf("Validate = %v, want ErrValidation", err)
			}
		})
	}
}

func TestCoerceAttrValue(t *testing.T) {
	strDef := UserAttrDef{Key: "dept", Type: UserAttrString}
	numDef := UserAttrDef{Key: "level", Type: UserAttrNumber}
	boolDef := UserAttrDef{Key: "vip", Type: UserAttrBoolean}
	cases := []struct {
		def  UserAttrDef
		raw  string
		want string
		ok   bool
	}{
		{strDef, "eng", "eng", true},
		{strDef, "", "", true},
		{numDef, "3", "3", true},
		{numDef, "3.5", "3.5", true},
		{numDef, "abc", "", false},
		{numDef, "", "", false},
		{boolDef, "true", "true", true},
		{boolDef, "FALSE", "false", true},
		{boolDef, "1", "true", true},
		{boolDef, "0", "false", true},
		{boolDef, "yes", "", false},
		{boolDef, "", "", false},
	}
	for _, tc := range cases {
		got, err := CoerceAttrValue(tc.def, tc.raw)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("Coerce(%s, %q) = (%q, %v), want (%q, nil)", tc.def.Key, tc.raw, got, err, tc.want)
		}
		if !tc.ok && !errors.Is(err, ErrValidation) {
			t.Errorf("Coerce(%s, %q) = (%q, %v), want ErrValidation", tc.def.Key, tc.raw, got, err)
		}
	}
}

func TestValidateAttrValues(t *testing.T) {
	defs := []UserAttrDef{
		{Key: "dept", Type: UserAttrString},
		{Key: "level", Type: UserAttrNumber},
		{Key: "tags", Type: UserAttrString, Multi: true},
	}
	got, err := ValidateAttrValues(defs, map[string][]string{
		"dept": {"eng"}, "level": {"3"}, "tags": {"a", "b"},
	})
	if err != nil {
		t.Fatalf("ValidateAttrValues = %v", err)
	}
	want := map[string][]string{"dept": {"eng"}, "level": {"3"}, "tags": {"a", "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValidateAttrValues = %v, want %v", got, want)
	}
	for name, values := range map[string]map[string][]string{
		"unknown key":     {"nosuch": {"x"}},
		"multi on single": {"dept": {"a", "b"}},
		"bad number":      {"level": {"abc"}},
	} {
		if _, err := ValidateAttrValues(defs, values); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}

func TestNormalizeAttrInput(t *testing.T) {
	got, err := NormalizeAttrInput(map[string]any{
		"dept":  "eng",
		"level": 3.0,
		"vip":   true,
		"tags":  []any{"a", "b"},
		"gone":  nil,
	})
	if err != nil {
		t.Fatalf("NormalizeAttrInput = %v", err)
	}
	want := map[string][]string{
		"dept": {"eng"}, "level": {"3"}, "vip": {"true"},
		"tags": {"a", "b"}, "gone": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeAttrInput = %v, want %v", got, want)
	}
	for name, input := range map[string]map[string]any{
		"nested object": {"dept": map[string]any{"x": 1}},
		"nested array":  {"dept": []any{[]any{"x"}}},
	} {
		if _, err := NormalizeAttrInput(input); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}

func TestTypedAttrValues(t *testing.T) {
	defs := []UserAttrDef{
		{Key: "dept", Type: UserAttrString},
		{Key: "level", Type: UserAttrNumber},
		{Key: "vip", Type: UserAttrBoolean},
		{Key: "tags", Type: UserAttrString, Multi: true},
		{Key: "scores", Type: UserAttrNumber, Multi: true},
	}
	got := TypedAttrValues(defs, map[string][]string{
		"dept": {"eng"}, "level": {"3"}, "vip": {"true"},
		"tags": {"a", "b"}, "scores": {"1.5", "2"},
		"unknown": {"x"}, "empty": {},
	})
	want := map[string]any{
		"dept": "eng", "level": 3.0, "vip": true,
		"tags": []any{"a", "b"}, "scores": []any{1.5, 2.0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TypedAttrValues = %v, want %v", got, want)
	}
}

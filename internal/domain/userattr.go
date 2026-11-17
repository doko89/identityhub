package domain

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Custom user attributes: the admin defines the schema (key, type,
// multi-valued) and every protocol serves the values — LDAP search
// attributes, OIDC claims and SAML assertion attributes. Keys double as
// the wire names on all three, so they must be lowercase LDAP-safe and
// must not collide with the built-in names below.
type UserAttrType string

const (
	UserAttrString  UserAttrType = "string"
	UserAttrNumber  UserAttrType = "number"
	UserAttrBoolean UserAttrType = "boolean"
)

// UserAttrSource records the last writer of a value. Mapped keys are
// upstream-managed: each directory sync replaces them wholesale, so an
// admin edit to a mapped key is overwritten by the next sync.
type UserAttrSource string

const (
	UserAttrAdmin UserAttrSource = "admin"
	UserAttrLDAP  UserAttrSource = "ldap"
)

// UserAttrDef is one row of user_attr_defs: one admin-defined attribute.
type UserAttrDef struct {
	ID    uuid.UUID
	Key   string
	Type  UserAttrType
	Multi bool
}

var attrKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// reservedAttrKeys are the built-in wire names no def may take: LDAP
// entry attributes, OIDC claims and SAML assertion attributes.
var reservedAttrKeys = map[string]bool{
	"uid": true, "cn": true, "sn": true, "mail": true, "memberof": true,
	"objectclass": true, "displayname": true, "ou": true, "dc": true, "dn": true,
	"sub": true, "iss": true, "aud": true, "exp": true, "iat": true,
	"auth_time": true, "nonce": true, "preferred_username": true,
	"email": true, "email_verified": true, "name": true, "groups": true,
}

// ReservedAttrKey reports whether key is a built-in wire name.
func ReservedAttrKey(key string) bool { return reservedAttrKeys[strings.ToLower(key)] }

// Validate checks def invariants: a lowercase LDAP-safe key outside the
// reserved names and a known type.
func (d UserAttrDef) Validate() error {
	if len(d.Key) == 0 || len(d.Key) > 64 || !attrKeyPattern.MatchString(d.Key) {
		return wrapValidation("attribute key must be 1-64 chars: a-z, 0-9, '-', starting with a letter")
	}
	if ReservedAttrKey(d.Key) {
		return wrapValidation(fmt.Sprintf("attribute key %q is reserved", d.Key))
	}
	switch d.Type {
	case UserAttrString, UserAttrNumber, UserAttrBoolean:
		return nil
	default:
		return wrapValidation(`attribute type must be "string", "number" or "boolean"`)
	}
}

// CoerceAttrValue validates one raw value against the def and returns
// its canonical stored form: numbers must parse (kept verbatim),
// booleans accept true/false/1/0 in any case and store "true"/"false".
func CoerceAttrValue(d UserAttrDef, raw string) (string, error) {
	switch d.Type {
	case UserAttrString:
		return raw, nil
	case UserAttrNumber:
		if _, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err != nil {
			return "", wrapValidation(fmt.Sprintf("attribute %q: %q is not a number", d.Key, raw))
		}
		return raw, nil
	case UserAttrBoolean:
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true", "1":
			return "true", nil
		case "false", "0":
			return "false", nil
		default:
			return "", wrapValidation(fmt.Sprintf("attribute %q: %q is not a boolean", d.Key, raw))
		}
	default:
		return "", wrapValidation(fmt.Sprintf("attribute %q has unknown type %q", d.Key, d.Type))
	}
}

// ValidateAttrValues checks keyed string values against the defs and
// returns their canonical form: unknown keys, type violations and
// multi-values on single-valued defs are validation errors. An empty
// slice clears the key.
func ValidateAttrValues(defs []UserAttrDef, values map[string][]string) (map[string][]string, error) {
	byKey := make(map[string]UserAttrDef, len(defs))
	for _, d := range defs {
		byKey[d.Key] = d
	}
	out := make(map[string][]string, len(values))
	for key, vals := range values {
		d, ok := byKey[key]
		if !ok {
			return nil, wrapValidation(fmt.Sprintf("unknown attribute %q", key))
		}
		if !d.Multi && len(vals) > 1 {
			return nil, wrapValidation(fmt.Sprintf("attribute %q takes a single value", key))
		}
		canonical := make([]string, 0, len(vals))
		for _, v := range vals {
			c, err := CoerceAttrValue(d, v)
			if err != nil {
				return nil, err
			}
			canonical = append(canonical, c)
		}
		out[key] = canonical
	}
	return out, nil
}

// NormalizeAttrInput converts admin JSON input (scalar or array of
// scalars per key, null clears) into keyed string values. Wrong JSON
// shapes and non-scalar elements are validation errors; type checking
// happens in ValidateAttrValues.
func NormalizeAttrInput(input map[string]any) (map[string][]string, error) {
	out := make(map[string][]string, len(input))
	for key, raw := range input {
		switch v := raw.(type) {
		case nil:
			out[key] = []string{}
		case string, float64, bool:
			s, err := attrScalarString(v)
			if err != nil {
				return nil, err
			}
			out[key] = []string{s}
		case []any:
			vals := make([]string, 0, len(v))
			for _, e := range v {
				s, err := attrScalarString(e)
				if err != nil {
					return nil, wrapValidation(fmt.Sprintf("attribute %q: values must be strings, numbers or booleans", key))
				}
				vals = append(vals, s)
			}
			out[key] = vals
		default:
			return nil, wrapValidation(fmt.Sprintf("attribute %q: value must be a scalar, an array or null", key))
		}
	}
	return out, nil
}

func attrScalarString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(t), nil
	default:
		return "", wrapValidation("attribute values must be strings, numbers or booleans")
	}
}

// TypedAttrValues renders stored values for JSON consumers (admin API,
// OIDC claims): single-valued defs become typed scalars, multi-valued
// defs become typed arrays. Keys without values are omitted.
func TypedAttrValues(defs []UserAttrDef, values map[string][]string) map[string]any {
	byKey := make(map[string]UserAttrDef, len(defs))
	for _, d := range defs {
		byKey[d.Key] = d
	}
	out := map[string]any{}
	for key, vals := range values {
		d, ok := byKey[key]
		if !ok || len(vals) == 0 {
			continue
		}
		if !d.Multi {
			out[key] = typedScalar(d.Type, vals[0])
			continue
		}
		arr := make([]any, 0, len(vals))
		for _, v := range vals {
			arr = append(arr, typedScalar(d.Type, v))
		}
		out[key] = arr
	}
	return out
}

func typedScalar(t UserAttrType, v string) any {
	switch t {
	case UserAttrNumber:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
		return v
	case UserAttrBoolean:
		return v == "true"
	default:
		return v
	}
}

// UpstreamAttrValues maps one snapshot entry's attributes to def IDs
// for ApplyUpstreamValues: unknown keys are skipped (no def) and
// uncoercible values are dropped, so upstream garbage never fails
// provisioning; single-valued defs keep the first valid value. Keys
// left empty are omitted, which clears their ldap-sourced rows.
func UpstreamAttrValues(defs []UserAttrDef, snap map[string][]string) map[uuid.UUID][]string {
	byKey := make(map[string]UserAttrDef, len(defs))
	for _, d := range defs {
		byKey[d.Key] = d
	}
	out := make(map[uuid.UUID][]string, len(snap))
	for key, vals := range snap {
		d, ok := byKey[key]
		if !ok {
			continue
		}
		var kept []string
		for _, v := range vals {
			if c, err := CoerceAttrValue(d, v); err == nil {
				kept = append(kept, c)
			}
		}
		if !d.Multi && len(kept) > 1 {
			kept = kept[:1]
		}
		if len(kept) == 0 {
			continue
		}
		out[d.ID] = kept
	}
	return out
}

// UserAttrStore is the port for attribute defs and per-user values.
type UserAttrStore interface {
	// CreateDef persists a def; duplicate keys map to ErrConflict.
	CreateDef(ctx context.Context, d UserAttrDef) (UserAttrDef, error)
	// ListDefs returns every def ordered by key.
	ListDefs(ctx context.Context) ([]UserAttrDef, error)
	// DeleteDef drops a def; its values cascade. Unknown keys map to
	// ErrNotFound.
	DeleteDef(ctx context.Context, key string) error
	// SetValues replaces the values of the given defs for one user;
	// an empty slice clears that def. Other defs are untouched.
	SetValues(ctx context.Context, userID uuid.UUID, values map[uuid.UUID][]string, source UserAttrSource) error
	// ApplyUpstreamValues replaces every ldap-sourced value of the
	// user with values (marked ldap) and clears ldap-sourced keys
	// missing from it. Defs present in values are replaced wholesale
	// regardless of previous source: mapped keys are upstream-managed.
	ApplyUpstreamValues(ctx context.Context, userID uuid.UUID, values map[uuid.UUID][]string) error
	// ValuesOfUser returns keyed values for one user.
	ValuesOfUser(ctx context.Context, userID uuid.UUID) (map[string][]string, error)
	// ValuesForUsers returns keyed values for many users in one query.
	ValuesForUsers(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]map[string][]string, error)
}

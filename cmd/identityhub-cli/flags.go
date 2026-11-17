package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// optional is a flag.Value recording whether it was set, so PATCH bodies
// only carry the keys the caller passed.
type optional struct {
	value string
	set   bool
}

func (o *optional) String() string { return o.value }

func (o *optional) Set(s string) error {
	o.value = s
	o.set = true
	return nil
}

// optBool parses an optional bool flag ("true"/"false"/"1"/"0").
func (o *optional) optBool() (bool, bool, error) {
	if !o.set {
		return false, false, nil
	}
	switch strings.ToLower(o.value) {
	case "true", "1":
		return true, true, nil
	case "false", "0":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("want true or false, got %q", o.value)
	}
}

// optInt parses an optional integer flag.
func (o *optional) optInt() (int, bool, error) {
	if !o.set {
		return 0, false, nil
	}
	n, err := strconv.Atoi(o.value)
	if err != nil {
		return 0, false, fmt.Errorf("want an integer, got %q", o.value)
	}
	return n, true, nil
}

// pageFlags adds --limit/--offset to fs and returns a query builder.
func pageFlags(fs *flag.FlagSet) func() url.Values {
	limit := fs.String("limit", "", "page size (max 200)")
	offset := fs.String("offset", "", "page offset")
	return func() url.Values {
		q := url.Values{}
		if *limit != "" {
			q.Set("limit", *limit)
		}
		if *offset != "" {
			q.Set("offset", *offset)
		}
		return q
	}
}

// promptSecret reads one line from stdin (used for passwords and shared
// secrets when the flag is omitted).
func promptSecret(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// urlValues converts a string map to query values, skipping blanks.
func urlValues(m map[string]string) url.Values {
	q := url.Values{}
	for k, v := range m {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q
}

// usageError marks a local argument error (as opposed to a server error).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return &usageError{fmt.Sprintf(format, args...)} }

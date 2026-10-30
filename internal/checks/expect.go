package checks

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Expect is a declarative comparison against an observed string value.
// Ops: eq, ne, in, not_in, ge, le, regex. String comparisons ignore case.
type Expect struct {
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

func Eq(v string) Expect       { return Expect{Op: "eq", Values: []string{v}} }
func In(v ...string) Expect    { return Expect{Op: "in", Values: v} }
func NotIn(v ...string) Expect { return Expect{Op: "not_in", Values: v} }
func GE(n int) Expect          { return Expect{Op: "ge", Values: []string{strconv.Itoa(n)}} }
func LE(n int) Expect          { return Expect{Op: "le", Values: []string{strconv.Itoa(n)}} }
func Matches(re string) Expect { return Expect{Op: "regex", Values: []string{re}} }

// Validate reports malformed expectations (used by the JSON rule loader).
func (e Expect) Validate() error {
	if len(e.Values) == 0 {
		return fmt.Errorf("expect.values is empty")
	}
	switch e.Op {
	case "eq", "ne", "in", "not_in":
	case "ge", "le":
		if _, err := strconv.ParseFloat(e.Values[0], 64); err != nil {
			return fmt.Errorf("expect %s needs a number, got %q", e.Op, e.Values[0])
		}
	case "regex":
		if _, err := regexp.Compile(e.Values[0]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown expect op %q", e.Op)
	}
	return nil
}

// Match compares the actual value.
func (e Expect) Match(actual string) (bool, error) {
	if err := e.Validate(); err != nil {
		return false, err
	}
	a := strings.TrimSpace(actual)
	fold := func(v string) bool { return strings.EqualFold(a, strings.TrimSpace(v)) }
	switch e.Op {
	case "eq", "in":
		return slices.ContainsFunc(e.Values, fold), nil
	case "ne", "not_in":
		return !slices.ContainsFunc(e.Values, fold), nil
	case "ge", "le":
		got, err := strconv.ParseFloat(strings.Fields(a + " x")[0], 64)
		if err != nil {
			return false, nil // non-numeric observation never satisfies a numeric bound
		}
		want, _ := strconv.ParseFloat(e.Values[0], 64)
		if e.Op == "ge" {
			return got >= want, nil
		}
		return got <= want, nil
	case "regex":
		return regexp.MustCompile(e.Values[0]).MatchString(a), nil
	}
	return false, nil
}

// Suggest returns a value that would satisfy the expectation, for remediation text.
func (e Expect) Suggest() string {
	if len(e.Values) == 0 || e.Op == "ne" || e.Op == "not_in" || e.Op == "regex" {
		return "<compliant value>"
	}
	return e.Values[0]
}

func (e Expect) String() string {
	switch e.Op {
	case "eq":
		return e.Values[0]
	case "ne":
		return "not " + e.Values[0]
	case "in":
		return "one of " + strings.Join(e.Values, "|")
	case "not_in":
		return "none of " + strings.Join(e.Values, "|")
	case "ge":
		return ">= " + e.Values[0]
	case "le":
		return "<= " + e.Values[0]
	case "regex":
		return "/" + e.Values[0] + "/"
	}
	return e.Op
}

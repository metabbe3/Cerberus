// Package masking compiles agent masking specs into regex rules and applies
// them to args/response trees before results leave the gateway.
package masking

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Spec is one masking rule as written in an agent's data JSON "masking" list.
// Scope "args" or "response" limits where the rule applies; "" means both.
type Spec struct {
	Pattern   string `json:"pattern"`
	Transform string `json:"transform"` // redact | mask | hash
	Scope     string `json:"scope"`     // args | response | "" (= both)
}

// Rule is a compiled Spec, ready for Apply.
type Rule struct {
	Re        *regexp.Regexp
	Transform string
	Scope     string
}

// Compile validates and pre-compiles every spec. It errors on a bad regex or
// a transform outside {redact, mask, hash}.
func Compile(specs []Spec) ([]Rule, error) {
	rules := make([]Rule, 0, len(specs))
	for _, s := range specs {
		switch s.Transform {
		case "redact", "mask", "hash":
		default:
			return nil, fmt.Errorf("masking: transform %q: %w", s.Transform, ErrBadTransform)
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return nil, fmt.Errorf("masking: pattern %q: %w", s.Pattern, err)
		}
		// A pattern that matches "" would insert the transform at every
		// character position — reject it (e.g. \d*, x*, empty).
		if re.MatchString("") {
			return nil, fmt.Errorf("masking: pattern %q matches the empty string", s.Pattern)
		}
		rules = append(rules, Rule{Re: re, Transform: s.Transform, Scope: s.Scope})
	}
	return rules, nil
}

// ErrBadTransform is returned by Compile for an unknown transform name.
var ErrBadTransform = fmt.Errorf("masking: unknown transform (want redact, mask or hash)")

// Apply walks v (map[string]any / []any / string leaves; anything else passes
// through untouched), applying rules whose scope matches, and deep-copies the
// containers it walks. changed reports whether any string was transformed.
func Apply(rules []Rule, scope string, v any) (out any, changed bool) {
	if len(rules) == 0 {
		return v, false
	}
	return apply(rules, scope, v)
}

func apply(rules []Rule, scope string, v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		// Keys are masked like values: a secret used as an object key must not
		// reach the audit log. If two keys mask to the same string the later
		// one wins — acceptable, since the originals were both secrets.
		out := make(map[string]any, len(t))
		changed := false
		for k, val := range t {
			nv, c := apply(rules, scope, val)
			nk, kc := transform(rules, scope, k)
			out[nk.(string)] = nv
			changed = changed || c || kc
		}
		return out, changed
	case []any:
		out := make([]any, len(t))
		changed := false
		for i, val := range t {
			nv, c := apply(rules, scope, val)
			out[i] = nv
			changed = changed || c
		}
		return out, changed
	case []map[string]any:
		out := make([]any, len(t))
		changed := false
		for i, val := range t {
			nv, c := apply(rules, scope, val)
			out[i] = nv
			changed = changed || c
		}
		return out, changed
	case string:
		return transform(rules, scope, t)
	default:
		return v, false
	}
}

func transform(rules []Rule, scope string, s string) (any, bool) {
	out := s
	changed := false
	for _, r := range rules {
		if r.Scope != "" && r.Scope != scope {
			continue
		}
		out = r.Re.ReplaceAllStringFunc(out, func(match string) string {
			changed = true
			switch r.Transform {
			case "redact":
				return "[REDACTED]"
			case "mask":
				return mask(match)
			case "hash":
				sum := sha256.Sum256([]byte(match))
				return "sha256:" + hex.EncodeToString(sum[:])[:16]
			default:
				return match
			}
		})
	}
	return out, changed
}

// mask keeps the first 2 and last 2 runes and replaces the middle with '*';
// strings of 4 or fewer runes become all '*'.
func mask(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-4) + string(r[len(r)-2:])
}

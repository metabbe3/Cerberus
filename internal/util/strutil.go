package util

import (
	"regexp"
	"strings"
)

// Str safely converts an interface value to string. Returns empty string if not a string.
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

var (
	zeroWidthRegex = regexp.MustCompile("[\u200b\u200c\u200d\u2060\u00ad\ufeff]")

	homoglyphMap = map[rune]rune{
		'а': 'a', 'А': 'a',
		'е': 'e', 'Е': 'e',
		'о': 'o', 'О': 'o',
		'р': 'p', 'Р': 'p',
		'с': 'c', 'С': 'c',
		'х': 'x', 'Х': 'x',
		'у': 'y', 'У': 'y',
		'г': 'r', 'Г': 'r',
	}

	urlTokenRegex = regexp.MustCompile(`(?i)(https?://)([^\s/:?#]+)`)
)

// NormalizeString strips word-joiner \u2060, soft-hyphen \u00ad, BOM \ufeff,
// zero-width chars (\u200b, \u200c, \u200d), and converts Latin-lookalike Cyrillic
// homoglyphs (a, e, o, p, c, x, y, г->r) to ASCII.
func NormalizeString(s string) string {
	if s == "" {
		return s
	}
	s = zeroWidthRegex.ReplaceAllString(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if mapped, ok := homoglyphMap[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeCommandURLs inspects command strings for URLs (e.g. http://167772161)
// or IP target tokens and normalizes integer/octal/hex host representations to dotted IPv4.
func NormalizeCommandURLs(cmd string) string {
	if cmd == "" {
		return cmd
	}
	return urlTokenRegex.ReplaceAllStringFunc(cmd, func(match string) string {
		sub := urlTokenRegex.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		proto := sub[1]
		host := sub[2]
		normHost := NormalizeIPString(host)
		return proto + normHost
	})
}

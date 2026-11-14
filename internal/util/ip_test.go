package util_test

import (
	"testing"

	"github.com/metabbe3/cerberus/internal/util"
)

func TestNormalizeIPString_Variants(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// Standard dotted decimal
		{"169.254.169.254", "169.254.169.254"},
		{"127.0.0.1", "127.0.0.1"},
		{"8.8.8.8", "8.8.8.8"},

		// Integer IP
		{"2852039166", "169.254.169.254"},
		{"2130706433", "127.0.0.1"},

		// Octal
		{"012.0.0.1", "10.0.0.1"},
		{"0251.0376.0251.0376", "169.254.169.254"},
		{"0177.0.0.1", "127.0.0.1"},
		{"025177524776", "169.254.169.254"},

		// Hex
		{"0xa9.0xfe.0xa9.0xfe", "169.254.169.254"},
		{"0xa9fea9fe", "169.254.169.254"},
		{"0x7f.0.0.1", "127.0.0.1"},
		{"0x7f000001", "127.0.0.1"},

		// IPv6 & IPv4-mapped IPv6
		{"::ffff:169.254.169.254", "169.254.169.254"},
		{"[::ffff:169.254.169.254]", "169.254.169.254"},
		{"::1", "::1"},
		{"[::1]", "::1"},

		// Domain names unchanged
		{"api.github.com", "api.github.com"},
		{"evil.com", "evil.com"},
		{"internal.corp", "internal.corp"},
	}

	for _, tc := range tests {
		got := util.NormalizeIPString(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeIPString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeURLResource(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"http://169.254.169.254/latest/meta-data/iam/", "http://169.254.169.254/latest/meta-data/iam/"},
		{"http://2852039166/latest/meta-data/iam/", "http://169.254.169.254/latest/meta-data/iam/"},
		{"http://0251.0376.0251.0376/latest/meta-data/iam/", "http://169.254.169.254/latest/meta-data/iam/"},
		{"http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/", "http://169.254.169.254/latest/meta-data/iam/"},
		{"http://[::ffff:169.254.169.254]/latest/meta-data/iam/", "http://169.254.169.254/latest/meta-data/iam/"},
		{"http://[::1]:8080/path", "http://[::1]:8080/path"},
		{"https://api.github.com/issues", "https://api.github.com/issues"},
	}

	for _, tc := range tests {
		got := util.NormalizeURLResource(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeURLResource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

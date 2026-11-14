package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NormalizeIPString normalizes host strings that represent IP addresses in various encodings
// (standard dotted-quad, octal, hex, 32-bit integer, bracketed IPv6, IPv4-mapped IPv6)
// into canonical IP string representations (e.g. "169.254.169.254", "127.0.0.1", "::1").
// If host is not a parseable IP representation (e.g. a domain name "api.github.com"),
// it is returned unchanged (with brackets stripped if present).
func NormalizeIPString(host string) string {
	h := strings.Trim(host, "[]")
	if h == "" {
		return host
	}

	// 1. Check if it's already parseable via net.ParseIP (covers standard v4 and v6)
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}

	// If it contains a colon, it was intended as IPv6 or host:port, but net.ParseIP failed.
	// Don't try IPv4 numeric conversions if colons are present.
	if strings.Contains(h, ":") {
		return h
	}

	// 2. Check for IPv4 alternative encodings (dotted quad with octal/hex, or single integer)
	if ip := parseIPv4Alternative(h); ip != nil {
		return ip.String()
	}

	return h
}

// parseIPv4Alternative handles inet_aton style encodings:
// - single integer (e.g. 2852039166, 0xa9fea9fe, 025177524776)
// - dotted parts with octal (0...), hex (0x...), decimal (e.g. 0251.0376.0251.0376, 012.0.0.1, 0xa9.0xfe.0xa9.0xfe)
func parseIPv4Alternative(s string) net.IP {
	parts := strings.Split(s, ".")
	if len(parts) == 1 {
		// Single 32-bit integer: decimal, hex, or octal
		part := parts[0]
		val, err := parseUintWithBase(part)
		if err != nil || val > 0xFFFFFFFF {
			return nil
		}
		return net.IPv4(byte((val>>24)&0xFF), byte((val>>16)&0xFF), byte((val>>8)&0xFF), byte(val&0xFF))
	}

	if len(parts) == 4 {
		var b [4]byte
		for i, p := range parts {
			val, err := parseUintWithBase(p)
			if err != nil || val > 255 {
				return nil
			}
			b[i] = byte(val & 0xFF)
		}
		return net.IPv4(b[0], b[1], b[2], b[3])
	}

	if len(parts) == 2 {
		// a.b: a is 8-bit, b is 24-bit
		a, err := parseUintWithBase(parts[0])
		if err != nil || a > 255 {
			return nil
		}
		b, err := parseUintWithBase(parts[1])
		if err != nil || b > 0xFFFFFF {
			return nil
		}
		return net.IPv4(byte(a&0xFF), byte((b>>16)&0xFF), byte((b>>8)&0xFF), byte(b&0xFF))
	}

	if len(parts) == 3 {
		// a.b.c: a is 8-bit, b is 8-bit, c is 16-bit
		a, err := parseUintWithBase(parts[0])
		if err != nil || a > 255 {
			return nil
		}
		b, err := parseUintWithBase(parts[1])
		if err != nil || b > 255 {
			return nil
		}
		c, err := parseUintWithBase(parts[2])
		if err != nil || c > 0xFFFF {
			return nil
		}
		return net.IPv4(byte(a&0xFF), byte(b&0xFF), byte((c>>8)&0xFF), byte(c&0xFF))
	}

	return nil
}

// parseUintWithBase parses a number string that can be decimal, octal (starts with 0 or 0o), or hex (starts with 0x).
func parseUintWithBase(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}
	// If it starts with 0x or 0X: hex
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	// If it starts with 0o or 0O: octal
	if strings.HasPrefix(strings.ToLower(s), "0o") {
		return strconv.ParseUint(s[2:], 8, 64)
	}
	// If it starts with 0 and has length > 1: octal (standard inet_aton octal)
	if len(s) > 1 && s[0] == '0' {
		isOctal := true
		for i := 1; i < len(s); i++ {
			if s[i] < '0' || s[i] > '7' {
				isOctal = false
				break
			}
		}
		if isOctal {
			return strconv.ParseUint(s, 8, 64)
		}
	}
	// Standard decimal
	return strconv.ParseUint(s, 10, 64)
}

// NormalizeURLResource replaces the host component in a URL or host:port/path string
// with its normalized IP address if the host represents an IP.
func NormalizeURLResource(raw string) string {
	if raw == "" {
		return raw
	}
	proto := ""
	after := raw
	if strings.Contains(raw, "://") {
		idx := strings.Index(raw, "://")
		proto = raw[:idx+3]
		after = raw[idx+3:]
	}

	// Split host_port from path
	hostPort := after
	path := ""
	if slashIdx := strings.Index(after, "/"); slashIdx != -1 {
		hostPort = after[:slashIdx]
		path = after[slashIdx:]
	}

	// Extract host and port
	host := hostPort
	port := ""
	if strings.HasPrefix(hostPort, "[") {
		// IPv6 bracketed: [::1]:80 or [::1]
		if closeIdx := strings.Index(hostPort, "]"); closeIdx != -1 {
			host = hostPort[:closeIdx+1]
			if closeIdx+1 < len(hostPort) && hostPort[closeIdx+1] == ':' {
				port = hostPort[closeIdx+1:] // includes ":"
			}
		}
	} else if colonIdx := strings.LastIndex(hostPort, ":"); colonIdx != -1 {
		host = hostPort[:colonIdx]
		port = hostPort[colonIdx:] // includes ":"
	}

	normHost := NormalizeIPString(host)
	// If normHost contains colons (IPv6), wrap in brackets
	if strings.Contains(normHost, ":") && !strings.HasPrefix(normHost, "[") {
		normHost = "[" + normHost + "]"
	}

	return proto + normHost + port + path
}

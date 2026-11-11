package util

// Str safely converts an interface value to string. Returns empty string if not a string.
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

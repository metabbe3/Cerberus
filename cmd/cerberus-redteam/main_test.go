package main

import (
	"strings"
	"testing"
)

func TestResolveAdminToken(t *testing.T) {
	tests := []struct {
		name    string
		flagVal string
		envVal  string
		want    string
		wantErr bool
	}{
		{
			name:    "flag precedence over env",
			flagVal: "sample-val-flag",
			envVal:  "sample-val-env",
			want:    "sample-val-flag",
			wantErr: false,
		},
		{
			name:    "fallback to env when flag is empty",
			flagVal: "",
			envVal:  "sample-val-env",
			want:    "sample-val-env",
			wantErr: false,
		},
		{
			name:    "whitespace flag falls back to env",
			flagVal: "   ",
			envVal:  "sample-val-env",
			want:    "sample-val-env",
			wantErr: false,
		},
		{
			name:    "error when both flag and env are empty",
			flagVal: "",
			envVal:  "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "error when both flag and env are whitespace",
			flagVal: "  \t ",
			envVal:  " \n ",
			want:    "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAdminToken(tc.flagVal, tc.envVal)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (token: %q)", got)
				}
				if !strings.Contains(err.Error(), "admin token required: set CERBERUS_ADMIN_TOKEN or -admin-token") {
					t.Fatalf("expected required token error message, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want token %q, got %q", tc.want, got)
			}
		})
	}
}

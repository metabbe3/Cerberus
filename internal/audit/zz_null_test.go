package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// Empty Since-window must serialize as [] not null (Owl Zod requires array).
func TestQueryEmptySinceReturnsArrayNotNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l, err := Open(ctx, filepath.Join(t.TempDir(), "t.db"), Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()
	// No events emitted; since in the future => zero rows.
	evs, err := l.Query(ctx, Filter{Since: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("audit: Query: %v", err)
	}
	b, _ := json.Marshal(evs)
	if string(b) == "null" {
		t.Fatalf("audit: empty query serialized as null, want []")
	}
}

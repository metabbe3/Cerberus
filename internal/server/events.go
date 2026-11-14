package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
)

// pingEvery is the SSE keepalive comment interval.
const pingEvery = 15 * time.Second

// events streams decisions as SSE: a replay of the last 50 ring events
// (oldest first), then every live event until the client disconnects, the
// server shuts down (ShutdownStreams), or the audit logger closes. Frames are
// `event: decision` + one JSON data line; a `: ping` comment keeps
// intermediaries from idling the connection out.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if s.deps.Audit == nil {
		writeErr(w, http.StatusServiceUnavailable, "audit unavailable")
		return
	}
	flusher := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Subscribe FIRST so no live event is missed during replay / connection setup (MC-16)
	ch, cancel := s.deps.Audit.Subscribe()
	defer cancel()

	// Replay: if Last-Event-ID header is present, replay ring events since that ID.
	// Otherwise, replay the last 50 ring events, oldest → newest.
	var replay []audit.Event
	var maxReplayedID int64
	if lastIDStr := r.Header.Get("Last-Event-ID"); lastIDStr != "" {
		if lastID, err := strconv.ParseInt(lastIDStr, 10, 64); err == nil && lastID > 0 {
			maxReplayedID = lastID
			replay = s.deps.Audit.Since(lastID)
		}
	}
	if replay == nil {
		recent := s.deps.Audit.Recent(50)
		replay = make([]audit.Event, len(recent))
		for i := range recent {
			replay[i] = recent[len(recent)-1-i]
		}
	}
	for _, ev := range replay {
		if ev.ID > maxReplayedID {
			maxReplayedID = ev.ID
		}
		if !writeFrame(w, ev) {
			return
		}
	}
	if err := flusher.Flush(); err != nil {
		return
	}

	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.streamsCtx.Done():
			return
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			if err := flusher.Flush(); err != nil {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.ID > 0 && ev.ID <= maxReplayedID {
				// Drop event already replayed from store / ring buffer (MC-16)
				continue
			}
			if ev.ID > maxReplayedID {
				maxReplayedID = ev.ID
			}
			if !writeFrame(w, ev) {
				return
			}
			if err := flusher.Flush(); err != nil {
				return
			}
		}
	}
}

// writeFrame emits one SSE event frame; false means the client went away.
// A frame whose JSON cannot marshal is skipped (nothing sensibly streamable).
func writeFrame(w io.Writer, ev audit.Event) bool {
	b, err := json.Marshal(ev)
	if err != nil {
		return true
	}
	if ev.ID > 0 {
		_, err = fmt.Fprintf(w, "id: %d\nevent: decision\ndata: %s\n\n", ev.ID, b)
	} else {
		_, err = fmt.Fprintf(w, "event: decision\ndata: %s\n\n", b)
	}
	if err != nil {
		return false
	}
	if ev.RuleID == "ops.rate_limited" || ev.RuleID == "ops.kill_switch" || ev.RuleID == "ops.break_glass" {
		if ev.ID > 0 {
			_, err = fmt.Fprintf(w, "id: %d\nevent: alert\ndata: %s\n\n", ev.ID, b)
		} else {
			_, err = fmt.Fprintf(w, "event: alert\ndata: %s\n\n", b)
		}
	}
	return err == nil
}

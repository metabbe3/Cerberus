package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	// Replay what is already in the ring, oldest → newest.
	recent := s.deps.Audit.Recent(50)
	for i := len(recent) - 1; i >= 0; i-- {
		if !writeFrame(w, recent[i]) {
			return
		}
	}
	if err := flusher.Flush(); err != nil {
		return
	}

	ch, cancel := s.deps.Audit.Subscribe()
	defer cancel()

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
	_, err = fmt.Fprintf(w, "event: decision\ndata: %s\n\n", b)
	return err == nil
}

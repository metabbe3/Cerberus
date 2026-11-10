package server

import (
	"encoding/json"
	"net/http"

	"github.com/metabbe3/cerberus/internal/engine"
)

// decide handles POST /v1/decide (stage = "") and the stage aliases
// /v1/decide/llm and /v1/decide/tool, which force the stage regardless of the
// body. The engine maps every failure mode to a deny, so the only client
// errors here are transport-level: 400 invalid json, 413, 415.
func (s *Server) decide(stage string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		var in engine.Input
		if err := json.Unmarshal(body, &in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if stage != "" {
			in.Stage = stage
		}
		d := s.deps.Engine.Decide(r.Context(), in)
		writeJSON(w, http.StatusOK, d)
	}
}
